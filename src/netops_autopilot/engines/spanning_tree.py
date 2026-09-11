"""Spanning-Tree BPDU Guard / Root Guard Audit.

A 30-year engineer keeps STP hygiene tight: BPDU guard on
every access port, root guard on the uplink side, edge
ports configured. This module is the typed
implementation: parse ``show spanning-tree interface``
output, surface typed :class:`StpInterface` records and a
typed :class:`StpGuardReport` with findings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class StpInterface:
    __test__ = False

    interface: str
    role: str = ""
    port_type: str = ""          # edge / network / auto
    bpdu_guard: bool = False
    root_guard: bool = False
    loop_guard: bool = False
    cost: int = 0


@dataclass(frozen=True)
class StpFinding:
    __test__ = False

    interface: str
    kind: str          # "no_bpdu_guard" / "no_root_guard"
    detail: str


@dataclass
class StpGuardReport:
    __test__ = False

    device: str
    interfaces: list[StpInterface] = field(default_factory=list)
    findings: list[StpFinding] = field(default_factory=list)

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def edge_count(self) -> int:
        return sum(
            1 for i in self.interfaces
            if i.port_type.lower() == "edge"
        )

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"STP: {self.interface_count} واجهة، "
                f"{self.finding_count} مشكلة"
            )
        return (
            f"STP: {self.interface_count} interface(s), "
            f"{self.finding_count} finding(s)"
        )


_STP_LINE = re.compile(
    r"^(?P<iface>\S+)\s+(?P<role>\S+)\s+(?P<type>\S+)"
    r"\s+(?P<bpdu>enabled|disabled)\s+(?P<root>enabled|disabled)"
    r"\s+(?P<loop>enabled|disabled)",
    re.MULTILINE,
)


def parse_stp_interfaces(
    device: str,
    output: str,
) -> StpGuardReport:
    """Parse ``show spanning-tree interface`` summary."""
    rep = StpGuardReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _STP_LINE.finditer(output):
        iface = m.group("iface")
        iface_obj = StpInterface(
            interface=iface,
            role=m.group("role"),
            port_type=m.group("type"),
            bpdu_guard=(m.group("bpdu") == "enabled"),
            root_guard=(m.group("root") == "enabled"),
            loop_guard=(m.group("loop") == "enabled"),
        )
        rep.interfaces.append(iface_obj)
        if iface_obj.port_type.lower() == "edge":
            if not iface_obj.bpdu_guard:
                rep.findings.append(StpFinding(
                    interface=iface,
                    kind="no_bpdu_guard",
                    detail=(
                        f"{iface} is edge port without BPDU guard."
                    ),
                ))
        elif iface_obj.port_type.lower() == "network":
            if not iface_obj.root_guard:
                rep.findings.append(StpFinding(
                    interface=iface,
                    kind="no_root_guard",
                    detail=(
                        f"{iface} is network port without root guard."
                    ),
                ))
    return rep
