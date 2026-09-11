"""DHCPv6 / SLAAC Analyzer — IPv6 address assignment.

A 30-year engineer runs DHCPv6 alongside SLAAC: stateless
SLAAC for endpoints, stateful DHCPv6 for servers, PD
(prefix delegation) for downstream routers.

This module is the typed implementation: parse Cisco
``show ipv6 dhcp`` / ``show ipv6 nd`` output, surface
typed :class:`Dhcpv6Binding` and :class:`SlaacAddress`
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
class SlaacAddress:
    __test__ = False

    address: str
    interface: str
    lifetime_seconds: int = 0
    preferred_seconds: int = 0


@dataclass(frozen=True)
class Dhcpv6Binding:
    __test__ = False

    client_duid: str
    iaid: str
    address: str
    lifetime_seconds: int = 0


@dataclass
class Ipv6AssignmentReport:
    __test__ = False

    device: str
    slaac: list[SlaacAddress] = field(default_factory=list)
    dhcpv6: list[Dhcpv6Binding] = field(default_factory=list)

    @property
    def slaac_count(self) -> int:
        return len(self.slaac)

    @property
    def dhcpv6_count(self) -> int:
        return len(self.dhcpv6)

    @property
    def total_addresses(self) -> int:
        return self.slaac_count + self.dhcpv6_count

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"IPv6: {self.slaac_count} SLAAC، "
                f"{self.dhcpv6_count} DHCPv6"
            )
        return (
            f"IPv6: {self.slaac_count} SLAAC, "
            f"{self.dhcpv6_count} DHCPv6"
        )


_SLAAC = re.compile(
    r"^(?P<addr>[0-9a-fA-F:]+)\s+(?P<iface>\S+)\s+"
    r"valid\s+(?P<valid_life>\d+)s\s+"
    r"preferred\s+(?P<pref_life>\d+)s",
    re.MULTILINE,
)
_DHCPV6 = re.compile(
    r"^Client:\s+(?P<duid>[0-9a-fA-F]+)\s+IAID:\s+(?P<iaid>\S+)\s+"
    r"Address:\s+(?P<addr>[0-9a-fA-F:]+)\s+"
    r"lifetime\s+(?P<life>\d+)",
    re.MULTILINE,
)


def parse_ipv6_nd(
    device: str,
    output: str,
) -> Ipv6AssignmentReport:
    """Parse ``show ipv6 nd`` output."""
    rep = Ipv6AssignmentReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _SLAAC.finditer(output):
        try:
            valid = int(m.group("valid_life"))
            pref = int(m.group("pref_life"))
        except ValueError:
            valid = pref = 0
        rep.slaac.append(SlaacAddress(
            address=m.group("addr"),
            interface=m.group("iface"),
            lifetime_seconds=valid,
            preferred_seconds=pref,
        ))
    for m in _DHCPV6.finditer(output):
        try:
            life = int(m.group("life"))
        except ValueError:
            life = 0
        rep.dhcpv6.append(Dhcpv6Binding(
            client_duid=m.group("duid"),
            iaid=m.group("iaid"),
            address=m.group("addr"),
            lifetime_seconds=life,
        ))
    return rep
