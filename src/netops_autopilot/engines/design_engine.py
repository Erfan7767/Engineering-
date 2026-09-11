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


# ------------------------------------------------------------------ harvest
def harvest_interfaces(report: CrawlReport) -> dict[str, tuple[str, ...]]:
    """Local port names per device from neighbor tables (merged view),
    port-name normalized with the device's family. Deterministic, dedup."""
    out: dict[str, list[str]] = {}
    for dev in report.devices:
        family = dev.identity.vendor_family if dev.identity else ""
        ports: list[str] = []
        for link in report.links:
            for ep in (link.endpoint_a, link.endpoint_b):
                if ep.device_ref != dev.device_ref or not ep.interface:
                    continue
                norm, _mapped = normalize_port(family, ep.interface)
                if norm and norm not in ports:
                    ports.append(norm)
        out[dev.device_ref] = sorted(ports)
    return {k: tuple(v) for k, v in out.items()}


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
        uplinks: list[UplinkAssignment] = []
        for ref in sorted(reachable):
            candidates: list[tuple[int, str, str, str, str]] = []
            for link in report.links:
                eps = [link.endpoint_a, link.endpoint_b]
                mine = next((e for e in eps if e.device_ref == ref), None)
                peer = next((e for e in eps if e.device_ref != ref), None)
                if mine is None or peer is None or mine.interface is None:
                    continue
                if peer.device_ref not in reachable:
                    continue
                try:
                    rank = _GRADE_RANK.index(link.fsm4_state)
                except ValueError:
                    rank = len(_GRADE_RANK) - 1
                candidates.append((rank, ref, mine.interface, peer.device_ref, peer.interface or "?"))
                break  # one uplink per device: the best discovered link only
            if candidates:
                candidates.sort(key=lambda c: (c[0], c[3], c[4]))
                rank, _r, port, peer_ref, peer_port = candidates[0]
                state = _GRADE_RANK[rank] if rank < len(_GRADE_RANK) else lf.UNKNOWN
                uplinks.append(UplinkAssignment(
                    device_ref=ref, local_port=normalize_port(family_of.get(ref, ""), port)[0] or port,
                    peer_ref=peer_ref,
                    peer_port=normalize_port(family_of.get(peer_ref, ""), peer_port)[0] or peer_port,
                    link_state=state,
                    reason=(f"best discovered uplink by FSM-4 grade ({state}); "
                            f"tie-break (peer, port)")))
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
        assignments: list[AccessAssignment] = []
        for ref in sorted(reachable):
            family = family_of.get(ref, "")
            free = [p for p in harvested.get(ref, ())
                    if p not in used.get(ref, set()) and p not in infrastructure.get(ref, set())]
            if not free:
                continue  # honest silence: nothing harvested beyond uplinks
            for zone_assign, port in zip(enduser, free):
                assignments.append(AccessAssignment(
                    device_ref=ref, port=port, zone=zone_assign.zone,
                    vlan_id=zone_assign.vlan_id,
                    reason=("first unused harvested port in deterministic order "
                            "(infrastructure ports with ANY neighbor evidence excluded); "
                            "pairs largest-need zone first; shortage visible in counts")))
            used.setdefault(ref, set()).update(free)
        return assignments

    # ------------------------------------------------------------------ IR
    def render_ir(self, design: SiteDesign, *, vendor_os_of: dict[str, str]) -> dict[str, ConfigIR]:
        """Per-device ConfigIR. UNMANAGED/unreachable devices get none.

        Node ordering is stable: VLAN model → L3 SVIs (router only) →
        uplinks (trunk) → access memberships. Every node is tagged
        REVERSIBLE_BY_REPLACE (archive-backed) or flagged, and carries the
        decision lineage in parameters['reason']."""
        out: dict[str, ConfigIR] = {}
        if design.blocked:
            return out
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
            svi_params = {
                "vlan_id": zone.vlan_id,
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


def _IR(device_ref: str, os_name: str, nodes) -> ConfigIR:
    if not nodes:
        return ConfigIR(title=f"{device_ref}: no-op", nodes=(
            IRNode(node_id="noop", target=_REF(device_ref),
                   operation=Operation.UPDATE, feature="documentation",
                   vendor_os=os_name or "UNKNOWN",
                   parameters={"note": "no planned change", "reason": "design produced no nodes"},
                   reversibility=Reversibility.REVERSIBLE_BY_REPLACE),))
    return ConfigIR(title=f"{device_ref}: site design apply", nodes=tuple(nodes))
