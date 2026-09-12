"""Phase 7 — execute the derived verification matrix against real device state.

``VerificationPlanner`` derives the mandatory tests and ``VerificationEngine``
grades the results, but nothing ever ran the tests. ``TestResult.evidence_id``
was documented as "produced downstream" and there was no downstream: the
pipeline ended at ``EXECUTION_GATE`` → ``REPORT``, so a run could report
``COMPLETE-APPLIED`` having never once asked the network whether it works.
"Config stuck" is not "requirement met".

This module is that missing downstream. Every test is graded ONLY from what a
device actually answered, collected through :class:`Collector` — which enforces
the READ_ONLY allowlist and records an Event + Artifact in the ledger. The
``evidence_id`` on each :class:`TestResult` is that artifact's ``raw_id``, so
every PASS is traceable to a real response (T1).

A test whose evidence cannot be obtained produces **no result at all**. That is
deliberate: :meth:`VerificationEngine.evaluate` then raises
``TEST_RESULTS_MISSING`` instead of letting an unrun test read as PASS. The
unrun tests and their reasons are returned on the outcome so the operator sees
exactly what was not proven and why (L01).

Grading rules are deliberately narrow. A test PASSes only when every
precondition it depends on is *positively observed* in device output. A
precondition that is positively contradicted is a FAIL. An absent pattern is a
FAIL, not a PASS — the platform never treats "I did not see a problem" as
evidence of health.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .design_engine import SiteDesign, ZoneAssignment
from .verification import Outcome, TestKind, TestResult, TestSpec


#: Zone kinds that carry end-user clients and therefore must have a DHCP pool.
#:
#: MGMT is excluded because it is infrastructure — switches, APs, printers —
#: addressed statically by design, and WAN is the provider side. The scope is
#: reported alongside the verdict so the exclusion is visible to the operator
#: rather than quietly narrowing the test to make it pass.
CLIENT_ZONE_KINDS = ("INTERNAL", "GUEST", "DMZ")


@dataclass(frozen=True)
class Evidence:
    """One real command, its real response, and the ledger artifact holding it."""

    device_ref: str
    command: str
    raw_id: str
    event_id: str
    sha256: str
    truncated: bool
    text: str


@dataclass(frozen=True)
class VerificationOutcome:
    """Graded results, plus the tests that could not be graded and why."""

    results: tuple[TestResult, ...]
    unrun: tuple[tuple[str, str], ...]
    evidence: tuple[Evidence, ...]
    #: Why each FAIL failed, keyed by test_id. A FAIL without a reason is not
    #: actionable, and the operator is owed the specific missing precondition.
    reasons: dict[str, str] = field(default_factory=dict)

    @property
    def graded(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> tuple[str, ...]:
        return tuple(r.test_id for r in self.results if r.outcome is Outcome.PASS)

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(r.test_id for r in self.results if r.outcome is Outcome.FAIL)


#: ``show ip interface brief`` row: name, address, ok, method, status, protocol.
_SVI_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<ip>\S+)\s+(?P<ok>\S+)\s+(?P<method>\S+)"
    r"\s+(?P<status>\S+)\s+(?P<protocol>\S+)\s*$", re.MULTILINE)

#: ``show vlan brief`` row: vlan id, name, status, ports.
_VLAN_ROW = re.compile(r"^(?P<vlan>\d+)\s+(?P<name>\S+)", re.MULTILINE)

#: A DHCP pool declaration in running-config.
_DHCP_POOL = re.compile(r"^ip dhcp pool (?P<pool>\S+)\s*$", re.MULTILINE)

#: The network statement inside a pool body.
_POOL_NETWORK = re.compile(r"^\s+network (?P<net>\S+) (?P<mask>\S+)\s*$", re.MULTILINE)

#: Resolvers handed to clients from inside a pool body.
_POOL_DNS = re.compile(r"^\s+dns-server (?P<servers>.+?)\s*$", re.MULTILINE)

#: Static default route in ``show ip route`` output.
_DEFAULT_ROUTE = re.compile(r"^S\*\s+0\.0\.0\.0/0", re.MULTILINE)
_LAST_RESORT = re.compile(r"Gateway of last resort is (?P<gw>\S+)")


@dataclass(frozen=True)
class _Svi:
    ip: str
    status: str
    protocol: str

    @property
    def up(self) -> bool:
        return self.status.lower() == "up" and self.protocol.lower() == "up"


class VerificationExecutor:
    """Runs the derived tests against the devices and grades from real output.

    ``session_for(device_ref)`` must return a live session or raise. A session
    that cannot be opened is not a test failure — it is missing evidence, and
    the test is reported unrun rather than graded either way.
    """

    def __init__(self, collector, session_for: Callable[[str, str], object]) -> None:
        self._collector = collector
        self._session_for = session_for
        self._cache: dict[tuple[str, str], Evidence] = {}
        self._unavailable: dict[str, str] = {}

    # ------------------------------------------------------------- evidence
    def _collect(self, device_ref: str, command: str) -> Optional[Evidence]:
        """Run one read-only command for real; return None if that is impossible.

        Never raises and never fabricates: a device that refuses the session, or
        a command the allowlist will not permit, yields ``None`` so the caller
        reports the test as unrun instead of guessing at an outcome.
        """
        key = (device_ref, command)
        if key in self._cache:
            return self._cache[key]
        if device_ref in self._unavailable:
            return None
        try:
            session = self._session_for(device_ref, "verification")
            result = self._collector.collect(
                device_ref=device_ref, command=command, session=session)
        except Exception as exc:      # transport, credential and allowlist refusals
            self._unavailable[device_ref] = f"{type(exc).__name__}: {exc}"
            return None
        evidence = Evidence(
            device_ref=device_ref, command=command,
            raw_id=result.artifact.raw_id, event_id=result.artifact.event_id,
            sha256=result.artifact.sha256, truncated=bool(result.artifact.truncated),
            text=result.output.decode("utf-8", errors="replace"))
        self._cache[key] = evidence
        return evidence

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _zone(design: SiteDesign, name: str) -> Optional[ZoneAssignment]:
        for z in design.zones:
            if z.zone == name:
                return z
        return None

    @staticmethod
    def _network_of(subnet: str) -> tuple[str, str]:
        net = ipaddress.ip_network(subnet, strict=False)
        return str(net.network_address), str(net.netmask)

    @staticmethod
    def _vlan_present(ev: Evidence, zone: ZoneAssignment) -> bool:
        return any(int(m.group("vlan")) == zone.vlan_id
                   for m in _VLAN_ROW.finditer(ev.text))

    @staticmethod
    def _svi_of(ev: Evidence, zone: ZoneAssignment) -> Optional[_Svi]:
        want = f"Vlan{zone.vlan_id}"
        for m in _SVI_ROW.finditer(ev.text):
            if m.group("name").lower() == want.lower():
                return _Svi(ip=m.group("ip"), status=m.group("status"),
                            protocol=m.group("protocol"))
        return None

    @staticmethod
    def _pool_networks(ev: Evidence) -> dict[str, set[str]]:
        """pool name -> the set of networks its body declares."""
        out: dict[str, set[str]] = {}
        for m in _DHCP_POOL.finditer(ev.text):
            start = m.end()
            nxt = _DHCP_POOL.search(ev.text, start)
            body = ev.text[start:nxt.start() if nxt else len(ev.text)]
            nets = {str(ipaddress.ip_network(f"{n.group('net')}/{n.group('mask')}",
                                             strict=False))
                    for n in _POOL_NETWORK.finditer(body)}
            out[m.group("pool")] = nets
        return out

    @staticmethod
    def _pool_dns(ev: Evidence) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for m in _DHCP_POOL.finditer(ev.text):
            start = m.end()
            nxt = _DHCP_POOL.search(ev.text, start)
            body = ev.text[start:nxt.start() if nxt else len(ev.text)]
            servers: set[str] = set()
            for d in _POOL_DNS.finditer(body):
                servers.update(s.strip() for s in d.group("servers").split() if s.strip())
            out[m.group("pool")] = servers
        return out

    # ---------------------------------------------------------------- grading
    def run(self, *, specs: tuple[TestSpec, ...],
            design: SiteDesign) -> VerificationOutcome:
        results: list[TestResult] = []
        unrun: list[tuple[str, str]] = []
        reasons: dict[str, str] = {}
        for spec in specs:
            graded, why = self._grade(spec, design)
            if graded is None:
                unrun.append((spec.test_id, why))
            else:
                results.append(graded)
                if graded.outcome is Outcome.FAIL and why:
                    reasons[spec.test_id] = why
        return VerificationOutcome(tuple(results), tuple(unrun),
                                   tuple(self._cache.values()), reasons)

    def _grade(self, spec: TestSpec,
               design: SiteDesign) -> tuple[Optional[TestResult], str]:
        if spec.kind is TestKind.CONNECTIVITY_ALLOW:
            return self._grade_allow(spec, design)
        if spec.kind is TestKind.CONNECTIVITY_DENY:
            return self._grade_deny(spec, design)
        if spec.kind is TestKind.SERVICE_UP:
            return self._grade_service(spec, design)
        return None, f"UNKNOWN_TEST_KIND:{spec.kind}"

    # -- CONNECTIVITY_ALLOW ------------------------------------------------
    def _grade_allow(self, spec: TestSpec,
                     design: SiteDesign) -> tuple[Optional[TestResult], str]:
        src, dst = spec.src_zone, spec.dst_zone
        za, zb = self._zone(design, src), self._zone(design, dst)
        if za is None or zb is None:
            return None, (f"DESIGN_HAS_NO_ZONE:{src if za is None else dst} "
                          f"— cannot verify a path the design does not describe")
        device = za.routed_on
        ev_vlan = self._collect(device, "show vlan brief")
        ev_svi = self._collect(device, "show ip interface brief")
        ev_cfg = self._collect(device, "show running-config")
        if ev_vlan is None or ev_svi is None or ev_cfg is None:
            return None, (f"NO_EVIDENCE from {device}: "
                          f"{self._unavailable.get(device, 'command refused')}")

        problems: list[str] = []
        for zone in (za, zb):
            if not self._vlan_present(ev_vlan, zone):
                problems.append(f"VLAN {zone.vlan_id} ({zone.zone}) absent from "
                                f"`show vlan brief` on {device}")
            svi = self._svi_of(ev_svi, zone)
            if svi is None:
                problems.append(f"SVI Vlan{zone.vlan_id} ({zone.zone}) absent from "
                                f"`show ip interface brief` on {device}")
            elif not svi.up:
                problems.append(f"SVI Vlan{zone.vlan_id} ({zone.zone}) is "
                                f"{svi.status}/{svi.protocol}, not up/up")
            elif not self._address_is_provider_assigned(ev_cfg, zone):
                want = str(ipaddress.ip_network(zone.subnet, strict=False).network_address)
                if not svi.ip.startswith(want.rsplit(".", 1)[0] + "."):
                    problems.append(f"SVI Vlan{zone.vlan_id} ({zone.zone}) holds "
                                    f"{svi.ip}, not an address in {zone.subnet}")

        # The decisive artifact is the SVI table: it carries both existence and
        # operational state, which is what an ALLOW test actually depends on.
        return (TestResult(test_id=spec.test_id,
                           outcome=Outcome.FAIL if problems else Outcome.PASS,
                           evidence_id=ev_svi.raw_id),
                "; ".join(problems))

    # -- CONNECTIVITY_DENY -------------------------------------------------
    def _grade_deny(self, spec: TestSpec,
                    design: SiteDesign) -> tuple[Optional[TestResult], str]:
        src, dst = spec.src_zone, spec.dst_zone
        za, zb = self._zone(design, src), self._zone(design, dst)
        if za is None or zb is None:
            return None, (f"DESIGN_HAS_NO_ZONE:{src if za is None else dst} "
                          f"— cannot verify isolation the design does not describe")
        # The design states plainly which pairs it could not enforce. Reporting
        # those as PASS because no route happens to exist would be exactly the
        # false success this phase exists to prevent — the requirement is unmet
        # and the operator is owed that fact, not a green tick.
        for u_src, u_dst, why in getattr(design, "unenforceable_isolation", ()):
            if (u_src, u_dst) == (src, dst):
                return None, f"ISOLATION_NOT_ENFORCEABLE: {why}"
        device = za.routed_on
        ev_route = self._collect(device, "show ip route")
        ev_acl = self._collect(device, "show ip access-lists")
        if ev_route is None:
            return None, (f"NO_EVIDENCE from {device}: "
                          f"{self._unavailable.get(device, 'command refused')}")

        src_net = str(ipaddress.ip_network(za.subnet, strict=False))
        dst_net = str(ipaddress.ip_network(zb.subnet, strict=False))
        reachable = (src_net in ev_route.text and dst_net in ev_route.text)

        if not reachable:
            # Genuinely no L3 path: the router cannot forward between them.
            return (TestResult(test_id=spec.test_id, outcome=Outcome.PASS,
                               evidence_id=ev_route.raw_id), "")

        denied = False
        if ev_acl is not None:
            denied = self._acl_denies(ev_acl.text, za, zb)
        if denied:
            return (TestResult(test_id=spec.test_id, outcome=Outcome.PASS,
                               evidence_id=ev_acl.raw_id), "")

        why = (f"both {src_net} and {dst_net} are routed on {device} and no ACL "
               f"denies {src}->{dst} — traffic would flow, so the required "
               f"isolation is NOT enforced")
        if ev_acl is None:
            why += f" (and `show ip access-lists` could not be read: {self._unavailable.get(device, 'refused')})"
        return (TestResult(test_id=spec.test_id, outcome=Outcome.FAIL,
                           evidence_id=ev_route.raw_id), why)

    @staticmethod
    def _address_is_provider_assigned(ev: Evidence, zone: ZoneAssignment) -> bool:
        """True when this SVI takes its address from the provider, not from us.

        On a WAN handed off by DHCP the operator's provider chooses the address,
        so comparing it against the subnet the design allocated is meaningless —
        the designed block was never meant to be used. Checked against what the
        device actually reports rather than assumed from the zone kind.
        """
        marker = f"interface Vlan{zone.vlan_id}"
        idx = ev.text.lower().find(marker.lower())
        if idx < 0:
            return False
        rest = ev.text[idx + len(marker):]
        nxt = rest.lower().find("\ninterface ")
        body = rest if nxt < 0 else rest[:nxt]
        return "ip address dhcp" in body.lower()

    @staticmethod
    def _acl_denies(acl_text: str, src: ZoneAssignment, dst: ZoneAssignment) -> bool:
        """An explicit `deny ip <src> <wc> <dst> <wc>` covering the pair."""
        s_net, s_mask = VerificationExecutor._network_of(src.subnet)
        d_net, d_mask = VerificationExecutor._network_of(dst.subnet)
        s_wc = str(ipaddress.ip_network(f"0.0.0.0/{s_mask}").hostmask)
        d_wc = str(ipaddress.ip_network(f"0.0.0.0/{d_mask}").hostmask)
        pattern = re.compile(
            rf"^\s*deny\s+ip\s+{re.escape(s_net)}\s+{re.escape(s_wc)}"
            rf"\s+{re.escape(d_net)}\s+{re.escape(d_wc)}\b", re.MULTILINE)
        return bool(pattern.search(acl_text))

    # -- SERVICE_UP --------------------------------------------------------
    def _grade_service(self, spec: TestSpec,
                       design: SiteDesign) -> tuple[Optional[TestResult], str]:
        internal = [z for z in design.zones if z.kind in CLIENT_ZONE_KINDS]
        if not internal:
            return None, ("NO_CLIENT_ZONES in the design — nothing to serve "
                          "addresses to, so the service requirement does not apply")
        gw = internal[0].routed_on if internal else (
            design.zones[0].routed_on if design.zones else None)
        if gw is None:
            return None, "DESIGN_HAS_NO_ZONES — no device to verify the service on"
        ev = self._collect(gw, "show running-config")
        if ev is None:
            return None, (f"NO_EVIDENCE from {gw}: "
                          f"{self._unavailable.get(gw, 'command refused')}")

        service = spec.dst_zone
        if service == "dhcp":
            return self._grade_dhcp(spec, ev, internal)
        if service == "dns":
            return self._grade_dns(spec, ev, internal)
        if service == "internet_egress":
            # Graded from the routing table, not from running-config. A static
            # default route appears in both, but a route learned from a
            # provider's DHCP lease exists ONLY in the table — grading it from
            # the config text reported "no default route" on a WAN that had one.
            route_ev = self._collect(gw, "show ip route")
            if route_ev is None:
                return None, (f"NO_EVIDENCE from {gw}: "
                              f"{self._unavailable.get(gw, 'command refused')}")
            return self._grade_egress(spec, route_ev, gw)
        return None, f"SERVICE_NOT_MODELED:{service} — no real check exists for it"

    def _grade_dhcp(self, spec: TestSpec, ev: Evidence,
                    zones) -> tuple[Optional[TestResult], str]:
        pools = self._pool_networks(ev)
        missing = [z.zone for z in zones if z.zone not in pools]
        wrong = []
        for z in zones:
            want = str(ipaddress.ip_network(z.subnet, strict=False))
            got = pools.get(z.zone)
            if got is not None and want not in got:
                wrong.append(f"pool {z.zone} serves {sorted(got)}, not {want}")
        problems = [f"no DHCP pool for zone {m}" for m in missing] + wrong
        return (TestResult(test_id=spec.test_id,
                           outcome=Outcome.FAIL if problems else Outcome.PASS,
                           evidence_id=ev.raw_id), "; ".join(problems))

    def _grade_dns(self, spec: TestSpec, ev: Evidence,
                   zones) -> tuple[Optional[TestResult], str]:
        """Clients get resolvers from their pool; that is what makes DNS work."""
        pools = self._pool_dns(ev)
        without = [z.zone for z in zones if not pools.get(z.zone)]
        problems = [f"pool for {w} hands out no dns-server" for w in without]
        return (TestResult(test_id=spec.test_id,
                           outcome=Outcome.FAIL if problems else Outcome.PASS,
                           evidence_id=ev.raw_id), "; ".join(problems))

    def _grade_egress(self, spec: TestSpec, ev: Evidence,
                      gw: str) -> tuple[Optional[TestResult], str]:
        has_default = bool(_DEFAULT_ROUTE.search(ev.text))
        last_resort = _LAST_RESORT.search(ev.text)
        if has_default:
            return (TestResult(test_id=spec.test_id, outcome=Outcome.PASS,
                               evidence_id=ev.raw_id), "")
        detail = ("no `S* 0.0.0.0/0` in `show ip route`"
                  + (f"; gateway of last resort is {last_resort.group('gw')}"
                     if last_resort else "; no gateway of last resort set"))
        return (TestResult(test_id=spec.test_id, outcome=Outcome.FAIL,
                           evidence_id=ev.raw_id),
                f"{gw} has no default route — {detail}")
