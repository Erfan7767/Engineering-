"""Routing Protocol Neighbor Engine — OSPF / BGP neighbor state.

A 30-year network engineer asks "is my OSPF neighbor up? how
many BGP sessions are established?". This module parses the
output of ``show ip ospf neighbor`` and ``show ip bgp
summary`` and returns typed, evidence-tagged reports.

What it does:

* Parses OSPF neighbor output: Neighbor ID, State, Interface,
  Dead time.
* Parses BGP summary output: Neighbor, V, AS, State/PfxRcd,
  Up/Down.
* Classifies each neighbor as UP / PENDING / DOWN based on
  the state string.
* Returns a typed report with per-neighbor details.

What it does NOT do (typed, never silent):

* It does NOT pretend a missing neighbor is UP. A missing
  state column is UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class NeighborState(str, Enum):
    __test__ = False

    UP = "UP"
    PENDING = "PENDING"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class Protocol(str, Enum):
    __test__ = False

    OSPF = "OSPF"
    BGP = "BGP"
    EIGRP = "EIGRP"


@dataclass(frozen=True)
class RoutingNeighbor:
    __test__ = False

    protocol: Protocol
    neighbor_id: str
    state: NeighborState
    interface: str = ""
    uptime: str = ""
    details: str = ""


# OSPF: typical line: "10.0.0.2    1   FULL/DR  0:00:32  GigabitEthernet0/1"
_OSPF_PATTERN = re.compile(
    r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<pri>\d+)\s+"
    r"(?P<state>\S+)\s+(?P<dead>\d+:\d+:\d+)\s+(?P<intf>\S+)",
    re.MULTILINE,
)

# BGP summary lines: "<neighbor> <v> <as> <state> <pfx> <uptime>"
# We accept flexible spacing.
_BGP_PATTERN = re.compile(
    r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+(?P<v>\d+)\s+(?P<as>\d+)\s+"
    r"(?P<state>\S+)(?:\s+(?P<pfx>\d+))?(?:\s+(?P<up>\S+))?",
    re.MULTILINE,
)


def _classify_ospf_state(state: str) -> NeighborState:
    """Classify an OSPF state string.

    The state may have a suffix like /DR, /BDR, /DROTHER.
    We split on / and use the prefix.
    """
    s = state.upper().strip().split("/", 1)[0]
    if s.startswith("FULL"):
        return NeighborState.UP
    if s in ("2-WAY", "EXSTART", "EXCHANGE", "LOADING", "INIT"):
        return NeighborState.PENDING
    if s in ("DOWN", "ATTEMPT"):
        return NeighborState.DOWN
    return NeighborState.UNKNOWN


def _classify_bgp_state(state: str) -> NeighborState:
    """Classify a BGP state code."""
    s = state.strip()
    # Numeric: 1=idle, 2=connect, 3=active, 4=opensent, 5=openconfirm, 6=established
    try:
        n = int(s)
    except ValueError:
        # Words
        s_lower = s.lower()
        if s_lower == "established":
            return NeighborState.UP
        if s_lower in ("idle", "active", "connect", "opensent", "openconfirm"):
            return NeighborState.PENDING
        return NeighborState.UNKNOWN
    if n == 6:
        return NeighborState.UP
    if n in (4, 5):
        return NeighborState.PENDING
    return NeighborState.DOWN


def parse_ospf(output: str) -> list[RoutingNeighbor]:
    """Parse ``show ip ospf neighbor`` output."""
    if not output or not output.strip():
        return []
    nbrs: list[RoutingNeighbor] = []
    for m in _OSPF_PATTERN.finditer(output):
        nbrs.append(RoutingNeighbor(
            protocol=Protocol.OSPF,
            neighbor_id=m.group("id"),
            state=_classify_ospf_state(m.group("state")),
            interface=m.group("intf"),
            uptime=m.group("dead"),
            details=m.group("state"),
        ))
    return nbrs


def parse_bgp(output: str) -> list[RoutingNeighbor]:
    """Parse ``show ip bgp summary`` output."""
    if not output or not output.strip():
        return []
    nbrs: list[RoutingNeighbor] = []
    for m in _BGP_PATTERN.finditer(output):
        nbrs.append(RoutingNeighbor(
            protocol=Protocol.BGP,
            neighbor_id=m.group("id"),
            state=_classify_bgp_state(m.group("state")),
            interface="",
            uptime=m.group("up") or "",
            details=f"AS{m.group('as')}",
        ))
    return nbrs


@dataclass
class RoutingReport:
    __test__ = False

    device_ref: str
    ospf: list[RoutingNeighbor] = field(default_factory=list)
    bgp: list[RoutingNeighbor] = field(default_factory=list)

    @property
    def ospf_up(self) -> int:
        return sum(1 for n in self.ospf if n.state == NeighborState.UP)

    @property
    def ospf_down(self) -> int:
        return sum(1 for n in self.ospf if n.state == NeighborState.DOWN)

    @property
    def bgp_up(self) -> int:
        return sum(1 for n in self.bgp if n.state == NeighborState.UP)

    @property
    def bgp_down(self) -> int:
        return sum(1 for n in self.bgp if n.state == NeighborState.DOWN)

    @property
    def overall_verdict(self) -> str:
        if self.ospf_down or self.bgp_down:
            return "DEGRADED"
        if not self.ospf and not self.bgp:
            return "UNKNOWN"
        return "HEALTHY"


def render(r: RoutingReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: RoutingReport) -> str:
    lines = [
        f"Routing neighbors for {r.device_ref}",
        f"  Verdict: {r.overall_verdict}",
    ]
    if r.ospf:
        lines.append(f"  OSPF: {r.ospf_up} up, {r.ospf_down} down "
                     f"of {len(r.ospf)} total")
        for n in r.ospf:
            lines.append(f"    [{n.state.value}] {n.neighbor_id} "
                         f"via {n.interface} ({n.uptime})")
    if r.bgp:
        lines.append(f"  BGP: {r.bgp_up} up, {r.bgp_down} down "
                     f"of {len(r.bgp)} total")
        for n in r.bgp:
            lines.append(f"    [{n.state.value}] {n.neighbor_id} "
                         f"{n.details} ({n.uptime})")
    if not r.ospf and not r.bgp:
        lines.append("  No OSPF or BGP neighbors found in the input.")
    return "\n".join(lines)


def _render_ar(r: RoutingReport) -> str:
    lines = [
        f"جيران التوجيه لـ {r.device_ref}",
        f"  النتيجة: {r.overall_verdict}",
    ]
    if r.ospf:
        lines.append(f"  OSPF: {r.ospf_up} نشط، {r.ospf_down} معطل "
                     f"من {len(r.ospf)} إجمالي")
        for n in r.ospf:
            lines.append(f"    [{n.state.value}] {n.neighbor_id} "
                         f"عبر {n.interface} ({n.uptime})")
    if r.bgp:
        lines.append(f"  BGP: {r.bgp_up} نشط، {r.bgp_down} معطل "
                     f"من {len(r.bgp)} إجمالي")
        for n in r.bgp:
            lines.append(f"    [{n.state.value}] {n.neighbor_id} "
                         f"{n.details} ({n.uptime})")
    if not r.ospf and not r.bgp:
        lines.append("  لا يوجد جيران OSPF أو BGP في المدخلات.")
    return "\n".join(lines)
