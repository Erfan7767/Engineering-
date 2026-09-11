"""Multicast PIM Engine — typed IGMP/PIM neighbor state.

A 30-year engineer runs multicast for IPTV / financial
feeds. The typical Day-N question: who's the RP? which
interface has IGMP joiners? what's the OIL?

This module is the typed implementation: parse Cisco
``show ip igmp groups`` and ``show ip pim neighbor``,
surface typed :class:`IgmpGroup` / :class:`PimNeighbor`
records.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class IgmpGroup:
    __test__ = False

    group: str
    interface: str
    uptime_seconds: int = 0
    last_reporter: str = ""


@dataclass(frozen=True)
class PimNeighbor:
    __test__ = False

    neighbor: str
    interface: str
    uptime_seconds: int = 0
    dr_priority: int = 0


@dataclass
class MulticastReport:
    __test__ = False

    device: str
    igmp_groups: list[IgmpGroup] = field(default_factory=list)
    pim_neighbors: list[PimNeighbor] = field(default_factory=list)

    @property
    def igmp_count(self) -> int:
        return len(self.igmp_groups)

    @property
    def pim_count(self) -> int:
        return len(self.pim_neighbors)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"Multicast: {self.igmp_count} مجموعة IGMP، "
                f"{self.pim_count} جار PIM"
            )
        return (
            f"Multicast: {self.igmp_count} IGMP group(s), "
            f"{self.pim_count} PIM neighbor(s)"
        )


_IGMP_GROUP = re.compile(
    r"^(?P<group>\d+\.\d+\.\d+\.\d+)\s+(?P<iface>\S+)\s+"
    r"(?P<uptime>\S+)\s+(?P<reporter>\d+\.\d+\.\d+\.\d+)",
    re.MULTILINE,
)
_PIM_NEIGHBOR = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+(?P<iface>\S+)\s+"
    r"(?P<uptime>\S+)\s+(?P<priority>\d+)",
    re.MULTILINE,
)


def _uptime_to_seconds(s: str) -> int:
    """Convert ``1d2h`` / ``00:12:34`` style into seconds."""
    if not s:
        return 0
    if ":" in s:
        parts = s.split(":")
        try:
            parts = [int(p) for p in parts]
        except ValueError:
            return 0
        while len(parts) < 3:
            parts.insert(0, 0)
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    secs = 0
    if s.endswith("d"):
        try:
            secs += int(s[:-1]) * 86400
        except ValueError:
            pass
    elif s.endswith("h"):
        try:
            secs += int(s[:-1]) * 3600
        except ValueError:
            pass
    elif s.endswith("m"):
        try:
            secs += int(s[:-1]) * 60
        except ValueError:
            pass
    elif s.endswith("s"):
        try:
            secs += int(s[:-1])
        except ValueError:
            pass
    return secs


def parse_igmp_groups(
    device: str,
    output: str,
) -> MulticastReport:
    """Parse ``show ip igmp groups``."""
    rep = MulticastReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _IGMP_GROUP.finditer(output):
        rep.igmp_groups.append(IgmpGroup(
            group=m.group("group"),
            interface=m.group("iface"),
            uptime_seconds=_uptime_to_seconds(
                m.group("uptime"),
            ),
            last_reporter=m.group("reporter"),
        ))
    return rep


def parse_pim_neighbors(
    device: str,
    output: str,
) -> MulticastReport:
    """Parse ``show ip pim neighbor``."""
    rep = MulticastReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _PIM_NEIGHBOR.finditer(output):
        try:
            prio = int(m.group("priority"))
        except ValueError:
            prio = 0
        rep.pim_neighbors.append(PimNeighbor(
            neighbor=m.group("neighbor"),
            interface=m.group("iface"),
            uptime_seconds=_uptime_to_seconds(
                m.group("uptime"),
            ),
            dr_priority=prio,
        ))
    return rep
