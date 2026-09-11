"""IPv6 Engine — typed dual-stack operations.

A 30-year engineer runs IPv4 + IPv6 side-by-side. The
typical Day-N question: is RA coming in? is the link-local
valid? what's the SLAAC address?

This module is the typed implementation: parse Cisco /
Junos ``show ipv6 interface`` output, surface typed
:class:`Ipv6Interface` and :class:`Ipv6Report`.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Ipv6Interface:
    __test__ = False

    name: str
    link_local: str = ""
    global_addresses: tuple[str, ...] = ()
    admin_up: bool = False
    oper_up: bool = False
    ra_received: bool = False
    mtu: int = 1500
    nd_suppress: bool = False

    @property
    def has_global(self) -> bool:
        return any(
            not a.startswith("fe80:")
            for a in self.global_addresses
        )

    @property
    def is_dual_stack(self) -> bool:
        return len(self.global_addresses) >= 1


@dataclass
class Ipv6Report:
    __test__ = False

    device: str
    interfaces: list[Ipv6Interface] = field(default_factory=list)

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def up_count(self) -> int:
        return sum(1 for i in self.interfaces if i.oper_up)

    @property
    def dual_stack_count(self) -> int:
        return sum(1 for i in self.interfaces if i.is_dual_stack)

    @property
    def no_ra_count(self) -> int:
        return sum(
            1 for i in self.interfaces
            if i.admin_up and i.oper_up and not i.ra_received
        )

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"IPv6: {self.interface_count} واجهة\n"
                f"  نشطة: {self.up_count}\n"
                f"  ثنائية المكدس: {self.dual_stack_count}\n"
                f"  بدون RA: {self.no_ra_count}"
            )
        return (
            f"IPv6: {self.interface_count} interface(s)\n"
            f"  Up: {self.up_count}\n"
            f"  Dual-stack: {self.dual_stack_count}\n"
            f"  No RA: {self.no_ra_count}"
        )


# Cisco IOS-XE ``show ipv6 interface brief``:
# Interface              Status    Up Time    Address
# GigabitEthernet0/0     up        12:30:14   2001:db8::1
_CISCO_BRIEF = re.compile(
    r"^(?P<name>\S+)\s+(?P<status>up|down|administratively down|"
    r"shut)\s+(?P<uptime>\S+)\s+(?P<address>\S+)?",
    re.MULTILINE,
)


def parse_cisco_brief(
    device: str,
    output: str,
) -> Ipv6Report:
    """Parse Cisco ``show ipv6 interface brief``."""
    rep = Ipv6Report(device=device)
    if not output or not output.strip():
        return rep
    for m in _CISCO_BRIEF.finditer(output):
        name = m.group("name")
        # Skip the header line.
        if name.lower().startswith("interface"):
            continue
        status = m.group("status")
        up = status == "up"
        addresses: list[str] = []
        addr = (m.group("address") or "").strip()
        if addr and addr != "--":
            try:
                ipaddress.IPv6Address(addr)
                addresses.append(addr)
            except (ValueError, ipaddress.AddressValueError):
                pass
        rep.interfaces.append(Ipv6Interface(
            name=name,
            global_addresses=tuple(addresses),
            admin_up=True,
            oper_up=up,
        ))
    return rep
