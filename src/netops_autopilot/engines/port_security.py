"""Port Security / 802.1X Analyzer.

A 30-year engineer keeps unauthorized NICs off the LAN:
port-security with sticky MACs on access ports, 802.1X
on user-facing ports, voice VLAN for IP phones.

This module is the typed implementation: parse Cisco
``show port-security`` / ``show dot1x`` output, surface
typed :class:`PortSecurityStatus` records and a typed
:class:`PortSecurityReport` with findings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortSecurityStatus:
    __test__ = False

    interface: str
    enabled: bool = False
    max_mac: int = 1
    current_mac_count: int = 0
    violation_mode: str = "shutdown"
    aging_time: int = 0
    dot1x_enabled: bool = False

    @property
    def is_over_limit(self) -> bool:
        return self.current_mac_count > self.max_mac


@dataclass
class PortSecurityReport:
    __test__ = False

    device: str
    ports: list[PortSecurityStatus] = field(default_factory=list)

    @property
    def port_count(self) -> int:
        return len(self.ports)

    @property
    def enabled_count(self) -> int:
        return sum(1 for p in self.ports if p.enabled)

    @property
    def over_limit(self) -> list[PortSecurityStatus]:
        return [p for p in self.ports if p.is_over_limit]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"Port-security: {self.port_count} منفذ، "
                f"{self.enabled_count} مفعّل، "
                f"{len(self.over_limit)} متجاوز الحد"
            )
        return (
            f"Port-security: {self.port_count} port(s), "
            f"{self.enabled_count} enabled, "
            f"{len(self.over_limit)} over limit"
        )


_PORT_SEC = re.compile(
    r"^(?P<iface>\S+)\s+(?P<status>enabled|disabled)"
    r"\s+(?P<max>\d+)\s+(?P<cur>\d+)\s+(?P<violation>\S+)"
    r"\s+(?P<aging>\d+)",
    re.MULTILINE,
)


def parse_port_security(
    device: str,
    output: str,
) -> PortSecurityReport:
    """Parse ``show port-security`` summary."""
    rep = PortSecurityReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _PORT_SEC.finditer(output):
        try:
            max_mac = int(m.group("max"))
            cur = int(m.group("cur"))
            aging = int(m.group("aging"))
        except ValueError:
            max_mac = 1
            cur = 0
            aging = 0
        rep.ports.append(PortSecurityStatus(
            interface=m.group("iface"),
            enabled=(m.group("status") == "enabled"),
            max_mac=max_mac,
            current_mac_count=cur,
            violation_mode=m.group("violation"),
            aging_time=aging,
        ))
    return rep
