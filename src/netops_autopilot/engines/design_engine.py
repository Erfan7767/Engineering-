"""Design Engine — blueprint × discovered topology × IPAM ⇒ per-device IR.

Converts a COMPILED Network Intent + Blueprint + Crawl Report into a fully
deterministic site design and one ConfigIR per device:

* roles are EVIDENCE-selected: the router is the device directly attached
  to the WAN zone per the human's answer; L2/L3 capability comes from the
  Capability Matrix (E06) — UNKNOWN capability means the device is L2-only
  (never assumed, T2), and no IR node is planned requiring the unknown
  capability;
* VLAN ids are a fixed ascending assignment from a VLAN pool; zone→subnet
  uses IPAM ``subnet_for_hosts`` + ``allocate_subnet`` on a stable index —
  identical inputs produce the identical plan;
* uplinks come from discovered links (best FSM-4 grade, deterministic
  tie-break); access ports are the device's remaining local ports from
  interface harvest — a device with no unused harvested port simply gets
  no access assignment (visible in the plan), never an invented port;
* every plan entry and IR node carries the evidence/decision lineage that
  produced it (``reason`` codes), so the plan is auditable end-to-end.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..fsm import link_fsm as lf
from ..parsers.portnames import normalize_port
from .blueprints import Blueprint
from .capability import CapabilityEngine
from .config_ir import ConfigIR, IRNode, Operation, Reversibility
from .discovery_crawl import CrawlReport, DeviceResult, DeviceStatus
from .intent_compiler import NetworkIntent
from .ipam import gateway_address, parse_network, subnet_for_hosts

import ipaddress

#: FSM-4 grade quality for uplink selection (better = lower index).
_GRADE_RANK = (
    lf.PHYSICAL_PATH_VERIFIED,
    lf.DIRECT_NEIGHBOR_CONFIRMED,
    lf.DIRECT_NEIGHBOR_PROBABLE,
    lf.INFERRED,
    lf.ONE_SIDED,
    lf.INTERMEDIATE_SUSPECTED,
    lf.STALE,
    lf.UNKNOWN,
    lf.CONFLICTING,
)

#: VLAN pool and addressing parents (site defaults — operator-overridable).
DEFAULT_VLAN_START = 10
DEFAULT_SITE_BLOCK_V4 = "10.240.0.0/16"
DEFAULT_MGMT_OFFSET_INDEX = 0


@dataclass(frozen=True)
class ZoneAssignment:
    zone: str
    kind: str
    vlan_id: int
    subnet: str
    gateway: str
    routed_on: str        # device_ref of the L3 node serving this zone
    reason: str           # decision lineage


@dataclass(frozen=True)
class UplinkAssignment:
    device_ref: str
    local_port: str
    peer_ref: str
    peer_port: str
    link_state: str       # the FSM-4 grade this choice stands on
    reason: str


@dataclass(frozen=True)
class AccessAssignment:
    device_ref: str
    port: str
    zone: str
    vlan_id: int
    reason: str


@dataclass(frozen=True)
class DeviceRole:
    device_ref: str
    role: str             # ROUTER | L3_SWITCH_DIST | L2_ACCESS | UNMANAGED_NEIGHBOR
    capabilities: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SiteDesign:
    design_id: str
    roles: tuple[DeviceRole, ...]
    zones: tuple[ZoneAssignment, ...]
    uplinks: tuple[UplinkAssignment, ...]
    access: tuple[AccessAssignment, ...]
    mgmt_subnet: Optional[str]
    blocking_questions: tuple[str, ...]
    blocked: bool
    blocked_reasons: tuple[str, ...]
    #: Zone pairs the compiled policy requires to be DENIED, as ``(src, dst)``.
    #:
    #: The design carries them because it is the design that has to enforce
    #: them. Until it did, three of the six blueprints declared
    #: ``guest_isolation=True`` and nothing on any device implemented it: the
    #: router had every zone directly connected and no ACL, so guest traffic
    #: reached the corporate VLAN. Phase 7 reported that honestly as six
    #: CONNECTIVITY_DENY failures; this field is what closes them.
    denied_pairs: tuple[tuple[str, str], ...] = ()
    #: Pairs the policy requires DENIED that this platform cannot enforce, as
    #: ``(src, dst, reason)``.
    #:
    #: A zone whose address the provider assigns has no subnet the platform
    #: chose, so a `deny ip <that subnet>` rule would name a network that does
    #: not exist on the device — configuration that looks correct, passes
    #: review, and protects nothing. Emitting it would be worse than not
    #: emitting it, so the pair is reported instead (L01, T2).
    unenforceable_isolation: tuple[tuple[str, str, str], ...] = ()


# ------------------------------------------------------------------ harvest
_PORT_TOKEN = re.compile(r"(\d+|\D+)")


def port_sort_key(name: str) -> tuple:
    """Natural (numeric-aware) ordering for port names.

    Plain ``sorted()`` puts ``gi1/0/10`` before ``gi1/0/2``, which is not how
    any engineer reads a patch panel — and access-port assignment order
    decides which VLAN lands on which socket, so the order is part of the
    design's determinism, not a cosmetic detail.
    """
    return tuple((0, int(tok)) if tok.isdigit() else (1, tok.lower())
                 for tok in _PORT_TOKEN.findall(name))


def harvest_interfaces(report: CrawlReport) -> dict[str, tuple[str, ...]]:
    """Local port names per device, port-name normalized, deterministic.

    Phase W: the port inventory (``show interfaces status``) is the primary
    source. Deriving ports only from neighbour tables — the previous
    behaviour — could never yield an end-user port, because the only ports a
    neighbour table names are exactly the ones the design reserves for
    infrastructure. The result was a structurally guaranteed
    ``0 access ports``: VLANs and gateways were created and nothing was ever
    plugged into them.

    Neighbour-derived ports are still merged in, so a device that answers no
    inventory command is no worse off than before. Order is the device's own
    port order (inventory first, then any link-only port), which is
    deterministic and matches how an engineer reads the box.
    """
    out: dict[str, list[str]] = {}
    for dev in report.devices:
        family = dev.identity.vendor_family if dev.identity else ""
        ports: list[str] = []
        # 1. the real inventory, in the order the device reported it
        for row in dev.interface_table:
            raw = row.get("port")
            if not raw:
                continue
            norm, _mapped = normalize_port(family, raw)
            if norm and norm not in ports:
                ports.append(norm)
        # 2. anything a neighbour table named that the inventory did not
        for link in report.links:
            for ep in (link.endpoint_a, link.endpoint_b):
                if ep.device_ref != dev.device_ref or not ep.interface:
                    continue
                norm, _mapped = normalize_port(family, ep.interface)
                if norm and norm not in ports:
                    ports.append(norm)
        # Natural order, so the assignment is replay-identical AND matches the
        # physical port numbering an operator walks the rack by.
        out[dev.device_ref] = tuple(sorted(ports, key=port_sort_key))
    return out


class DesignEngine:
    def __init__(self, capability: CapabilityEngine) -> None:
        """The real E06 engine: platforms whose families are absent return
        UNKNOWN — the safest possible capability answer (never an error)."""
        self._cap = capability

    # ---------------------------------------------------------------- design
    def design(
        self,
        *,
        intent: NetworkIntent,
        blueprint: Blueprint,
        report: CrawlReport,
        answers: dict[str, str],
        site_block_v4: str = DEFAULT_SITE_BLOCK_V4,
    ) -> SiteDesign:
        questions: list[str] = []
        reasons: list[str] = []
        if intent.status != "COMPILED":
            return SiteDesign(
                design_id="design-blocked", roles=(), zones=(), uplinks=(), access=(),
                mgmt_subnet=None, blocking_questions=tuple(q.code for q in intent.blocking_questions),
                blocked=True, blocked_reasons=("INTENT_NOT_COMPILED",))

        reachable = {d.device_ref: d for d in report.devices if d.status is DeviceStatus.COMPLETE}
        devices = sorted(reachable)
        if not devices:
            return SiteDesign("design-blocked", (), (), (), (), None, (),
                              True, ("NO_REACHABLE_DEVICE",))

        router_ref = (answers.get("router_device") or devices[0]).strip()
        if router_ref not in reachable:
            questions.append("router_device: on which discovered device does the WAN terminate?")
            router_ref = devices[0]
            reasons.append(f"router defaulted to seed/known device {router_ref!r} (was not discovered)")
        else:
            reasons.append(f"router = {router_ref!r} from operator answer 'router_device'")

        # --- roles -------------------------------------------------------
        roles: list[DeviceRole] = []
        family_of: dict[str, str] = {}
        version_of: dict[str, str] = {}
        for ref in devices:
            dev = reachable[ref]
            family = dev.identity.vendor_family if dev.identity else None
            family_of[ref] = family or "UNKNOWN"
            if dev.identity and dev.identity.version:
                version_of[ref] = dev.identity.version
        l3_caps = self._l3_capable(devices, family_of, version_of)
        for ref in devices:
            if ref == router_ref:
                roles.append(DeviceRole(ref, "ROUTER", l3_caps[ref],
                                        "router_device answer + capability matrix"))
            elif l3_caps[ref]:
                roles.append(DeviceRole(ref, "L3_SWITCH_DIST", l3_caps[ref],
                                        "L3 capability evidenced (matrix row + version)"))
            else:
                roles.append(DeviceRole(ref, "L2_ACCESS", (),
                                        "no L3 capability evidence ⇒ L2-only (never assumed)"))
        for ref in sorted(r.device_ref for r in report.devices if r.device_ref not in reachable):
            roles.append(DeviceRole(ref, "UNMANAGED_NEIGHBOR", (),
                                    "discovered but unreachable ⇒ OUTSIDE THE MANAGED SET; "
                                    "physical only until reachable (never silently included)"))

        # --- zones --------------------------------------------------------
        # Deterministic packing order (independent of declaration order):
        # coarsest prefix first (largest subnet), MGMT always first-among-
        # equals so the management segment lands on the site's zeroth block
        # — an operator-stable convention with zero overlap by IPAM index.
        MGMT_KIND_ORDER = ("MGMT", "WAN", "DMZ", "INTERNAL", "GUEST")

        def _zone_sort_key(zone) -> tuple[int, int, str]:
            hosts = blueprint.default_host_sizes.get(zone.name, 16)
            prefix = subnet_for_hosts(hosts)
            return (prefix, MGMT_KIND_ORDER.index(zone.kind.value), zone.name)

        # Sequential, overlap-free packing (an engineer's first-fit, not
        # per-prefix indices — those overlap across prefix lengths):
        # coarsest prefix first, cursor aligned to each block boundary.
        parent = parse_network(site_block_v4)
        cursor = int(parent.network_address)
        parent_end = int(parent.broadcast_address)
        zone_assigns: list[ZoneAssignment] = []
        next_vlan = DEFAULT_VLAN_START
        mgmt_subnet: Optional[str] = None
        for zone in sorted(intent.zones, key=_zone_sort_key):
            hosts = blueprint.default_host_sizes.get(zone.name)
            if hosts is None:
                questions.append(f"host_count[{zone.name}]: how many hosts in zone {zone.name!r}?")
                hosts = 16
                reasons.append(f"zone {zone.name!r} host size defaulted to 16 pending answer")
            prefix = subnet_for_hosts(hosts)
            block_size = 1 << (32 - prefix)
            cursor = ((cursor + block_size - 1) // block_size) * block_size
            if cursor + block_size - 1 > parent_end:
                return SiteDesign("design-blocked", tuple(roles), tuple(zone_assigns),
                                  (), (), None,
                                  tuple(sorted(questions)), True,
                                  tuple(reasons) + (f"SITE_BLOCK_EXHAUSTED: /{prefix} for zone "
                                                    f"{zone.name!r} does not fit in {site_block_v4}",))
            subnet = str(ipaddress.ip_network((cursor, prefix)))
            cursor += block_size
            vlan = next_vlan
            next_vlan += 10
            gateway = gateway_address(subnet, 1)
            zone_assigns.append(ZoneAssignment(
                zone=zone.name, kind=zone.kind.value, vlan_id=vlan, subnet=subnet,
                gateway=gateway, routed_on=router_ref,
                reason=(f"IPAM first-fit: site={site_block_v4} hosts={hosts} ⇒ /{prefix}; "
                        f"vlan={vlan} (pool step 10); gw=first usable")))
            if zone.kind.value == "MGMT":
                mgmt_subnet = subnet

        # --- uplinks -------------------------------------------------------
        uplinks = self._uplinks(report, reachable, family_of)

        # --- access ---------------------------------------------------------
        access = self._access_ports(report, reachable, family_of, uplinks,
                                    zone_assigns, blueprint)

        blocked = bool(questions)
        return SiteDesign(
            design_id=f"design:{router_ref}:{len(zone_assigns)}zones",
            roles=tuple(roles), zones=tuple(zone_assigns), uplinks=tuple(uplinks),
            access=tuple(access), mgmt_subnet=mgmt_subnet,
            blocking_questions=tuple(sorted(questions)),
            denied_pairs=effective_denied_pairs(intent),
            unenforceable_isolation=_unenforceable_isolation(
                intent, zone_assigns, answers.get("wan_handoff")),
            blocked=blocked,
            blocked_reasons=tuple(reasons + ([f"HQ-PENDING: {q}" for q in questions] if questions else [])),
        )

    # --------------------------------------------------------------- helpers
    def _l3_capable(self, devices: list[str], family_of: dict[str, str],
                    version_of: Optional[dict[str, str]] = None) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        for ref in devices:
            caps: list[str] = []
            family = family_of.get(ref) or ""
            version = (version_of or {}).get(ref)
            for feature, state in self._probe_matrix(family, version):
                if state:
                    caps.append(feature)
            out[ref] = tuple(sorted(caps))
        return out

    def _probe_matrix(self, family: str, version: Optional[str]) -> list[tuple[str, bool]]:
        """Capability probes against E06. A device whose VERSION was not
        observed cannot satisfy any matrix version constraint; probing with
        it would still return UNKNOWN (fail-closed), so the honest path is
        to skip the probe and yield NO capability — never an assumption.
        YES/PARTIAL plannable states only (candidate pool, not decision)."""
        if not family or family == "UNKNOWN" or not version:
            return []
        from .capability import CapabilityValue
        plannable = (CapabilityValue.YES, CapabilityValue.PARTIAL)
        out: list[tuple[str, bool]] = []
        for feature in ("static_routing", "ospf", "svi"):
            try:
                state = self._cap.lookup(family, version, feature, "configure")
            except Exception:
                state = CapabilityValue.UNKNOWN
            out.append((feature, state in plannable))
        return out

    def _uplinks(self, report: CrawlReport, reachable: dict[str, DeviceResult],
                 family_of: dict[str, str]) -> list[UplinkAssignment]:
        """One assignment for every device-port that carries neighbour evidence.

        Both ends of a link have to be trunks or the link does not carry the
        design's VLANs. The previous rule — one uplink per device, the best
        link only — left the router's *other* downstream ports in their default
        access mode, so the switch cabled to them sat on VLAN 1 while the
        design claimed a trunk existed there. A three-device fabric exposed it:
        the core's uplink was announced in the plan and never configured.

        Two further defects are fixed with it:

        * ``break`` sat inside the link loop, so ``candidates`` never held more
          than one entry and the ``.sort()`` below it was dead code. The
          ``reason`` string still claimed grade-based selection with a
          (peer, port) tie-break — a false statement about what the engine did.
        * Every candidate link is now ranked and the best grade per local port
          wins, so the reason describes the selection that actually happened.
        """
        # (device_ref, normalized local port) → best (rank, peer, peer port)
        best: dict[tuple[str, str], tuple[int, str, str]] = {}
        for link in report.links:
            try:
                rank = _GRADE_RANK.index(link.fsm4_state)
            except ValueError:
                rank = len(_GRADE_RANK) - 1
            for mine, peer in ((link.endpoint_a, link.endpoint_b),
                               (link.endpoint_b, link.endpoint_a)):
                if mine.device_ref not in reachable:
                    continue
                if peer.device_ref not in reachable:
                    continue
                if mine.interface is None or peer.interface is None:
                    continue  # no local port ⇒ cannot be configured, never guessed
                port = normalize_port(family_of.get(mine.device_ref, ""),
                                      mine.interface)[0] or mine.interface
                peer_port = normalize_port(family_of.get(peer.device_ref, ""),
                                           peer.interface)[0] or peer.interface
                key = (mine.device_ref, port)
                prior = best.get(key)
                if prior is None or (rank, peer.device_ref, peer_port) < prior:
                    best[key] = (rank, peer.device_ref, peer_port)

        uplinks: list[UplinkAssignment] = []
        for (ref, port), (rank, peer_ref, peer_port) in sorted(best.items()):
            state = _GRADE_RANK[rank] if rank < len(_GRADE_RANK) else lf.UNKNOWN
            uplinks.append(UplinkAssignment(
                device_ref=ref, local_port=port, peer_ref=peer_ref,
                peer_port=peer_port, link_state=state,
                reason=(f"port carries neighbour evidence (FSM-4 {state}); best "
                        f"grade per local port, tie-break (peer, port)")))
        return uplinks

    def _access_ports(self, report: CrawlReport, reachable: dict[str, DeviceResult],
                      family_of: dict[str, str], uplinks: list[UplinkAssignment],
                      zones: list[ZoneAssignment], blueprint: Blueprint) -> list[AccessAssignment]:
        used: dict[str, set[str]] = {}
        for up in uplinks:
            used.setdefault(up.device_ref, set()).add(up.local_port)
        harvested = harvest_interfaces(report)
        # infrastructure reservation: every port that carries ANY neighbor
        # evidence is an infrastructure port (never end-user access), even
        # when it was not selected as THE uplink (redundant paths converge).
        infrastructure: dict[str, set[str]] = {}
        for ref in reachable:
            infra_ports: set[str] = set()
            for link in report.links:
                for ep in (link.endpoint_a, link.endpoint_b):
                    if ep.device_ref == ref and ep.interface:
                        infra_ports.add(normalize_port(family_of.get(ref, ""), ep.interface)[0] or ep.interface)
            infrastructure[ref] = infra_ports
        enduser = [a for a in zones if a.kind in ("INTERNAL", "GUEST", "DMZ")]
        # Serve the largest internal-ish zone first (shortage is visible).
        enduser.sort(key=lambda a: -blueprint.default_host_sizes.get(a.zone, 0))
        weights = _zone_weights(enduser, blueprint)
        assignments: list[AccessAssignment] = []
        for ref in sorted(reachable):
            family = family_of.get(ref, "")
            free = [p for p in harvested.get(ref, ())
                    if p not in used.get(ref, set()) and p not in infrastructure.get(ref, set())]
            if not free:
                continue  # honest silence: nothing harvested beyond uplinks
            # A routed zone whose VLAN has no member port has a
            # protocol-down SVI: the address is configured and the zone cannot
            # forward a packet. The weighted distribution below serves only
            # INTERNAL/GUEST/DMZ, so MGMT and WAN were left with an SVI and no
            # port at all. That was invisible on the sample device only because
            # its baseline already had those VLANs populated; on any device
            # where the VLAN is new the WAN came up empty and there was no
            # internet. Reserve one harvested port per such zone, taken from
            # the high end so end-user ports are unaffected, and name the port
            # the operator has to cable.
            for zone_assign in zones:
                if zone_assign.kind in ("INTERNAL", "GUEST", "DMZ"):
                    continue                    # served by the distribution
                if zone_assign.routed_on != ref or not free:
                    continue
                port = free.pop()               # highest harvested port
                what = ("provider handoff" if zone_assign.kind == "WAN"
                        else "out-of-band management")
                assignments.append(AccessAssignment(
                    device_ref=ref, port=port, zone=zone_assign.zone,
                    vlan_id=zone_assign.vlan_id,
                    reason=(f"designated {what} port {port}: an SVI on a VLAN "
                            f"with no member port is protocol-down, so zone "
                            f"'{zone_assign.zone}' could not forward. Cable the "
                            f"{what} into {port}.")))
                used.setdefault(ref, set()).add(port)
            # Phase W: spread the free ports across the zones in proportion to
            # their planned host counts. The previous `zip(enduser, free)`
            # gave every zone exactly ONE port regardless of size, so a
            # 96-host users zone and an 8-host mgmt zone both got a single
            # socket. Deterministic weighted round-robin: same inputs, same
            # assignment, replay-identical.
            for port, zone_assign in zip(free, _weighted_cycle(enduser, weights)):
                assignments.append(AccessAssignment(
                    device_ref=ref, port=port, zone=zone_assign.zone,
                    vlan_id=zone_assign.vlan_id,
                    reason=(f"unused harvested port in deterministic order "
                            f"(infrastructure ports with ANY neighbor evidence excluded); "
                            f"distributed in proportion to planned host count "
                            f"(weight {weights[zone_assign.zone]})")))
            used.setdefault(ref, set()).update(free)
        return assignments

    # ------------------------------------------------------------------ IR
    def render_ir(self, design: SiteDesign, *, vendor_os_of: dict[str, str],
                  answers: Optional[dict[str, str]] = None) -> dict[str, ConfigIR]:
        """Per-device ConfigIR. UNMANAGED/unreachable devices get none.

        Node ordering is stable: VLAN model → L3 SVIs (router only) →
        uplinks (trunk) → access memberships. Every node is tagged
        REVERSIBLE_BY_REPLACE (archive-backed) or flagged, and carries the
        decision lineage in parameters['reason'].

        ``answers`` carries operator-supplied values that must never be
        guessed — currently the client DNS servers for DHCP pools. Absent
        values leave the corresponding template line unbound, which the
        renderer reports rather than inventing."""
        out: dict[str, ConfigIR] = {}
        if design.blocked:
            return out
        answers = dict(answers or {})
        role_of = {r.device_ref: r.role for r in design.roles}
        for zone in design.zones:
            target = zone.routed_on
            if role_of.get(target) not in {"ROUTER", "L3_SWITCH_DIST"}:
                continue
            os_name = vendor_os_of.get(target, "UNKNOWN")
            nodes: list[IRNode] = list(out[target].nodes) if target in out else []
            nodes.append(IRNode(
                node_id=f"vlan-{zone.zone}-{zone.vlan_id}",
                target=_REF(target),
                operation=Operation.CREATE, feature="vlan", vendor_os=os_name,
                parameters={"vlan_id": zone.vlan_id, "name": zone.zone, "reason": zone.reason},
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                provides=(f"vlan:{zone.zone}",)))
            # The operator is asked to describe the WAN handoff and the answer
            # used to be validated as present and then never read — the same
            # "asked, answered, ignored" defect that dropped the DNS servers.
            # When the handoff is DHCP the provider assigns both the address and
            # the default route, so configuring the designed static gateway here
            # would be wrong AND would leave the site with no internet egress.
            if zone.kind == "WAN" and handoff_is_dhcp(answers.get("wan_handoff")):
                nodes.append(IRNode(
                    node_id=f"wan-dhcp-{zone.zone}",
                    target=_REF(target),
                    operation=Operation.CREATE, feature="wan_dhcp", vendor_os=os_name,
                    parameters={
                        "vlan_id": zone.vlan_id, "zone": zone.zone,
                        # The interface that takes the provider's lease.
                        "interface": zone.zone,
                        "reason": (f"WAN handoff declared DHCP "
                                   f"({answers.get('wan_handoff')!r}): the provider assigns "
                                   f"the address and installs the default route, so no static "
                                   f"gateway is configured and none is invented"),
                    },
                    reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                    requires=(f"vlan:{zone.zone}",),
                    provides=(f"l3:{zone.zone}", "egress:default")))
                out[target] = _IR(target, os_name, tuple(nodes))
                continue
            svi_params = {
                "vlan_id": zone.vlan_id,
                # The name of the L3 interface this address belongs to. It is
                # the SAME value the vlan node above used for its `name`, so
                # the address is bound to the interface that node created
                # rather than to a name each renderer has to guess. Vendor
                # templates for RouterOS/Junos/FortiOS all address the SVI by
                # interface name; without this they could only report
                # NOT_MODELED for the one node a design cannot work without.
                "name": zone.zone,
                # CIDR form — the syntax Junos/RouterOS renderers require.
                "address": f"{zone.gateway}/{zone.subnet.split('/')[1]}",
                # Split form — IOS/IOS-XE `ip address <ip> <dotted-mask>`
                # rejects CIDR, so the renderer must not have to guess.
                "address_ip": zone.gateway,
                "address_mask": _prefix_to_mask(zone.subnet.split("/")[1]),
                "address_prefix": zone.subnet.split("/")[1],
                "zone": zone.zone, "reason": f"gateway={zone.gateway} (IPAM first usable)",
            }
            # An unrepresentable value is omitted, never stringified: the
            # renderer then reports NOT_MODELED for the node (T2) instead of
            # emitting a line the device would reject.
            svi_params = {k: v for k, v in svi_params.items() if v is not None}
            nodes.append(IRNode(
                node_id=f"svi-{zone.zone}",
                target=_REF(target),
                operation=Operation.CREATE, feature="svi", vendor_os=os_name,
                parameters=svi_params,
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                requires=(f"vlan:{zone.zone}",),
                provides=(f"l3:{zone.zone}",)))
            # DHCP for the zones clients actually attach to. Without a pool the
            # VLAN and gateway exist but nothing ever gets an address, so the
            # network is dead on arrival for end users.
            if zone.kind in ("INTERNAL", "GUEST", "DMZ"):
                prefix = zone.subnet.split("/")[1]
                mask = _prefix_to_mask(prefix)
                exclusion = _dhcp_exclusion(zone.subnet, zone.gateway)
                # IOS `dns-server` takes a SPACE-separated list. The operator
                # is asked for commas because that is how people write it;
                # emitting the comma form verbatim would be rejected by the
                # device, so it is normalized here rather than at the wire.
                dns = " ".join(
                    tok for tok in re.split(r"[,;\s]+", (answers.get("dns_servers") or "").strip())
                    if tok)
                if mask and exclusion:
                    dhcp_params = {
                        "pool": zone.zone,
                        # The interface the pool serves. Same name the vlan and
                        # svi nodes used, so a vendor whose DHCP server binds to
                        # an interface (RouterOS, FortiOS, Junos) names the one
                        # that actually exists instead of guessing.
                        "interface": zone.zone,
                        # CIDR form, for vendors whose DHCP syntax takes a prefix
                        # length rather than a dotted mask.
                        "prefix": prefix,
                        "network": str(ipaddress.ip_network(zone.subnet, strict=False).network_address),
                        "netmask": mask,
                        "gateway": zone.gateway,
                        "exclude_first": exclusion[0],
                        "exclude_last": exclusion[1],
                        "reason": (f"pool for zone {zone.zone}; first {DHCP_RESERVED_HOSTS} usable "
                                   f"addresses reserved for gateway/infrastructure"),
                    }
                    pool_range = _dhcp_pool_range(zone.subnet, exclusion[1])
                    if pool_range:
                        # RouterOS declares a pool as an explicit assignable
                        # window rather than a network plus an exclusion, so the
                        # window is derived here from the SAME subnet and the SAME
                        # exclusion the IOS form uses. Two vendors can then never
                        # disagree about which addresses get handed out.
                        dhcp_params["pool_first"], dhcp_params["pool_last"] = pool_range
                    if dns:
                        dhcp_params["dns"] = dns
                    nodes.append(IRNode(
                        node_id=f"dhcp-{zone.zone}",
                        target=_REF(target),
                        operation=Operation.CREATE, feature="dhcp", vendor_os=os_name,
                        parameters=dhcp_params,
                        reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                        requires=(f"l3:{zone.zone}",),
                        provides=(f"dhcp:{zone.zone}",)))
                else:
                    # Not invented, not silently dropped: a zone with no
                    # computable pool is visible in the render as NOT_MODELED.
                    nodes.append(IRNode(
                        node_id=f"dhcp-{zone.zone}",
                        target=_REF(target),
                        operation=Operation.CREATE, feature="dhcp", vendor_os=os_name,
                        parameters={"reason": (f"NO_DHCP_POOL: subnet {zone.subnet} has no "
                                               f"computable IPv4 exclusion block (T2)")},
                        reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                        requires=(f"l3:{zone.zone}",),
                        provides=()))
            out[target] = _IR(target, os_name, tuple(nodes))

        # --- inter-zone isolation ----------------------------------------
        # The policy matrix says these pairs must not reach each other. Every
        # zone gateway lives on this router, so without an explicit deny the
        # router forwards between them and the requirement is unmet — silently.
        # Enforced inbound on the SOURCE zone's SVI, denies first and an
        # explicit `permit ip any any` last, so nothing outside the denied set
        # is dropped by accident (a deny-only ACL would black-hole the zone).
        zone_by_name = {z.zone: z for z in design.zones}
        provider_assigned = {z.zone for z in design.zones
                             if z.kind == "WAN"
                             and handoff_is_dhcp(answers.get("wan_handoff"))}
        by_src: dict[str, list[str]] = {}
        for src, dst in design.denied_pairs:
            by_src.setdefault(src, []).append(dst)
        for src in sorted(by_src):
            src_zone = zone_by_name.get(src)
            if src_zone is None:
                continue
            target = src_zone.routed_on
            if role_of.get(target) not in {"ROUTER", "L3_SWITCH_DIST"}:
                continue
            os_name = vendor_os_of.get(target, "UNKNOWN")
            nodes = list(out[target].nodes) if target in out else []
            acl_name = f"ACL_{src.upper()}_IN"
            src_net = ipaddress.ip_network(src_zone.subnet, strict=False)
            for dst in sorted(by_src[src]):
                dst_zone = zone_by_name.get(dst)
                if dst_zone is None:
                    continue
                if src in provider_assigned or dst in provider_assigned:
                    # Not emitted. See SiteDesign.unenforceable_isolation: a
                    # deny naming a provider-chosen subnet matches nothing.
                    continue
                dst_net = ipaddress.ip_network(dst_zone.subnet, strict=False)
                nodes.append(IRNode(
                    node_id=f"acl-deny-{src}-{dst}", target=_REF(target),
                    operation=Operation.CREATE, feature="acl_deny", vendor_os=os_name,
                    parameters={
                        "acl_name": acl_name,
                        "src_net": str(src_net.network_address),
                        "src_wc": str(src_net.hostmask),
                        "dst_net": str(dst_net.network_address),
                        "dst_wc": str(dst_net.hostmask),
                        # Prefix lengths for vendors whose filter syntax is
                        # CIDR-only. Same two networks, second notation — not a
                        # second opinion about what the subnet is.
                        "src_prefix": src_net.prefixlen,
                        "dst_prefix": dst_net.prefixlen,
                        "reason": (f"policy requires {src}->{dst} DENIED; enforced "
                                   f"inbound on the {src} gateway"),
                    },
                    reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                    requires=(f"l3:{src}",), provides=()))
            nodes.append(IRNode(
                node_id=f"acl-permit-{src}", target=_REF(target),
                operation=Operation.CREATE, feature="acl_permit", vendor_os=os_name,
                parameters={"acl_name": acl_name,
                            "reason": (f"everything not denied above stays reachable "
                                       f"from {src}; without it the ACL black-holes "
                                       f"the zone")},
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                requires=(f"l3:{src}",), provides=()))
            nodes.append(IRNode(
                node_id=f"acl-apply-{src}", target=_REF(target),
                operation=Operation.UPDATE, feature="acl_apply", vendor_os=os_name,
                parameters={"acl_name": acl_name, "vlan_id": src_zone.vlan_id,
                            "reason": f"{acl_name} applied inbound on Vlan{src_zone.vlan_id}"},
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                requires=(f"l3:{src}",), provides=()))
            out[target] = _IR(target, os_name, tuple(nodes))

        for up in design.uplinks:
            ref = up.device_ref
            os_name = vendor_os_of.get(ref, "UNKNOWN")
            existing = list(out[ref].nodes) if ref in out else []
            nodes = list(existing) + [IRNode(
                node_id=f"uplink-{up.local_port}",
                target=_REF(ref), operation=Operation.UPDATE, feature="trunk",
                vendor_os=os_name,
                parameters={"interface": up.local_port, "peer": f"{up.peer_ref}:{up.peer_port}",
                            "allowed_vlans": [z.vlan_id for z in design.zones],
                            "link_state": up.link_state, "reason": up.reason},
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                requires=tuple(f"vlan:{z.zone}" for z in design.zones),)]
            out[ref] = _IR(ref, os_name, tuple(nodes))
        for acc in design.access:
            ref = acc.device_ref
            os_name = vendor_os_of.get(ref, "UNKNOWN")
            existing = list(out[ref].nodes) if ref in out else []
            nodes = list(existing) + [IRNode(
                node_id=f"access-{acc.port}",
                target=_REF(ref), operation=Operation.UPDATE, feature="access",
                vendor_os=os_name,
                parameters={"interface": acc.port, "vlan_id": acc.vlan_id, "zone": acc.zone,
                            "reason": acc.reason},
                reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                requires=(f"vlan:{acc.zone}",),)]
            out[ref] = _IR(ref, os_name, tuple(nodes))
        return {ref: ir for ref, ir in sorted(out.items()) if ir.nodes}


def _zone_weights(enduser: list, blueprint: Blueprint) -> dict:
    """Integer distribution weights from the blueprint's planned host counts.

    Falls back to 1 so a zone with no declared size still receives ports
    rather than being silently starved.
    """
    weights: dict = {}
    for zone_assign in enduser:
        size = blueprint.default_host_sizes.get(zone_assign.zone, 0)
        weights[zone_assign.zone] = max(1, int(size))
    return weights


def _weighted_cycle(enduser: list, weights: dict) -> list:
    """A deterministic weighted round-robin over ``enduser``.

    Emits each zone ``weight`` times, interleaved by largest-remainder so the
    sequence stays balanced (users, users, voice, users, …) instead of
    exhausting one zone before starting the next. Pure function of its inputs.
    """
    if not enduser:
        return []
    total = sum(weights.get(z.zone, 1) for z in enduser)
    # Largest-remainder apportionment over a fixed cycle length so the ratio
    # between zones is honoured even for small port counts.
    cycle_len = max(len(enduser), min(total, 12))
    quota: list[list] = []
    for zone_assign in enduser:
        w = weights.get(zone_assign.zone, 1)
        exact = cycle_len * w / total
        quota.append([zone_assign, int(exact), exact - int(exact)])
    given = sum(q[1] for q in quota)
    for entry in sorted(quota, key=lambda q: -q[2])[: cycle_len - given]:
        entry[1] += 1
    # Interleave: repeatedly take one slot from each zone that still has quota.
    out: list = []
    while True:
        progressed = False
        for entry in quota:
            if entry[1] > 0:
                out.append(entry[0])
                entry[1] -= 1
                progressed = True
        if not progressed:
            break
    return out


#: Addresses reserved at the bottom of every DHCP-served subnet for the
#: gateway and future infrastructure (printers, APs, servers with statics).
#: A pool that hands out its gateway address is a pool that breaks silently
#: the day someone gives that address to a printer.
DHCP_RESERVED_HOSTS = 10


def _dhcp_exclusion(subnet: str, gateway: str) -> Optional[tuple[str, str]]:
    """(first_excluded, last_excluded) for a subnet, or None if uncomputable.

    Reserves the first :data:`DHCP_RESERVED_HOSTS` usable addresses, always
    covering the gateway, and never runs past the last usable address — a
    pool with zero assignable addresses would be worse than no pool.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None                      # IPv6 uses SLAAC/RA, not this pool model
    hosts = list(net.hosts())
    if not hosts:
        return None
    first = hosts[0]
    reserve = min(DHCP_RESERVED_HOSTS, len(hosts))
    last = hosts[reserve - 1]
    # The gateway must be inside the excluded block.
    try:
        gw = ipaddress.ip_address(gateway)
    except ValueError:
        gw = None
    if gw is not None and gw in net and int(gw) > int(last):
        last = gw
    return (str(first), str(last))


def _dhcp_pool_range(subnet: str, exclude_last: str) -> Optional[tuple[str, str]]:
    """(first_assignable, last_assignable) for a pool, or None if uncomputable.

    RouterOS declares a pool as an explicit ``ranges=a-b`` window instead of a
    network plus an exclusion list, so the renderer needs the window itself. It
    is derived from the same subnet and the same exclusion block the IOS form
    uses, which keeps the two vendors in agreement about which addresses are
    actually handed out. Returns None rather than an invented range when the
    subnet leaves nothing assignable after the reserved block.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        last_excluded = ipaddress.ip_address(exclude_last)
    except ValueError:
        return None
    if net.version != 4:
        return None                      # IPv6 uses SLAAC/RA, not this pool model
    assignable = [h for h in net.hosts() if int(h) > int(last_excluded)]
    if not assignable:
        return None
    return str(assignable[0]), str(assignable[-1])


def _prefix_to_mask(prefix: str) -> Optional[str]:
    """Dotted-quad netmask for an IPv4 prefix length.

    IOS/IOS-XE ``ip address`` requires ``<ip> <dotted-mask>`` and rejects the
    CIDR form, so the IR carries both spellings and the renderer picks the one
    its vendor needs.

    Returns ``None`` for IPv6: IPv6 has no dotted mask, and silently emitting
    one would be a guess. The parameter is then left unbound, which makes the
    renderer mark that node NOT_MODELED (T2) — visible, never invented.
    """
    try:
        prefix_len = int(prefix)
    except (TypeError, ValueError):
        return None
    if not 0 <= prefix_len <= 32:
        return None
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)


def _REF(device_ref: str):
    from .config_ir import EntityRef
    return EntityRef(entity_type="DEVICE", entity_ref=device_ref)


def _unenforceable_isolation(intent, zones, wan_handoff) -> tuple[tuple[str, str, str], ...]:
    """Denied pairs the platform cannot express as a real ACL, and why.

    A DHCP-handoff WAN takes its address from the provider, so the subnet this
    platform allocated for it is never on the wire. Any deny rule naming it
    would match nothing, so the pair is reported rather than misconfigured.
    """
    if not handoff_is_dhcp(wan_handoff):
        return ()
    provider = {z.zone for z in zones if z.kind == "WAN"}
    out: list[tuple[str, str, str]] = []
    for src, dst in effective_denied_pairs(intent):
        for z in (src, dst):
            if z in provider:
                out.append((src, dst,
                            f"zone {z!r} takes its address from the provider (WAN "
                            f"handoff {wan_handoff!r}), so the allocated subnet is "
                            f"not on the wire and a deny rule naming it would match "
                            f"nothing — enforce this pair at the firewall or with a "
                            f"reflexive ACL"))
                break
    return tuple(out)


def effective_denied_pairs(intent: NetworkIntent) -> tuple[tuple[str, str], ...]:
    """The zone pairs whose effective policy is DENY.

    Computed with exactly the precedence rule :class:`VerificationPlanner`
    uses — lowest ``precedence`` wins — so the design enforces the same matrix
    the verification phase grades against. Two different interpretations of the
    same rule set is how a network ends up enforcing something other than what
    it was asked to enforce.
    """
    from .intent_compiler import RuleAction

    names = sorted({z.name for z in intent.zones})
    denied: list[tuple[str, str]] = []
    for src in names:
        for dst in names:
            rules = [r for r in intent.rules
                     if r.src_zone == src and r.dst_zone == dst]
            if not rules:
                continue
            effective = min(rules, key=lambda r: r.precedence)
            if effective.action is RuleAction.DENY:
                denied.append((src, dst))
    return tuple(denied)


def handoff_is_dhcp(handoff: Optional[str]) -> bool:
    """True when the operator declared that the provider assigns the WAN address.

    Only an explicit statement counts. An unrecognised handoff description is
    NOT assumed to be DHCP: putting a provider-assumed address on the WAN
    interface would be inventing the one thing the platform cannot know (L01).
    """
    text = (handoff or "").lower()
    return "dhcp" in text or "dynamic" in text


def _IR(device_ref: str, os_name: str, nodes) -> ConfigIR:
    if not nodes:
        return ConfigIR(title=f"{device_ref}: no-op", nodes=(
            IRNode(node_id="noop", target=_REF(device_ref),
                   operation=Operation.UPDATE, feature="documentation",
                   vendor_os=os_name or "UNKNOWN",
                   parameters={"note": "no planned change", "reason": "design produced no nodes"},
                   reversibility=Reversibility.REVERSIBLE_BY_REPLACE),))
    return ConfigIR(title=f"{device_ref}: site design apply", nodes=tuple(nodes))
