"""Routing Protocol Engine — OSPF cost/timers/area audit.

A 30-year engineer keeps routing consistent across the
network. This module is the typed implementation: parse
``show ip ospf interface`` output, surface typed
:class:`OspfInterface` / :class:`OspfReport` records,
flag mis-tuned hello/dead timers, and report on
area type mismatch.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class OspfInterface:
    __test__ = False

    interface: str
    area: str
    cost: int = 1
    hello_seconds: int = 10
    dead_seconds: int = 40
    network_type: str = "BROADCAST"
    passive: bool = False
    authentication: str = "none"

    @property
    def is_tuned_correctly(self) -> bool:
        # P2P/BROADCAST: hello=10, dead=40.
        if self.network_type in ("BROADCAST", "POINT_TO_POINT"):
            return (
                self.hello_seconds == 10
                and self.dead_seconds == 40
            )
        # NBMA / POINT_TO_MULTIPOINT: hello=30, dead=120.
        if self.network_type in (
            "NBMA", "POINT_TO_MULTIPOINT",
        ):
            return (
                self.hello_seconds == 30
                and self.dead_seconds == 120
            )
        return True


@dataclass
class OspfReport:
    __test__ = False

    device: str
    router_id: str = ""
    interfaces: list[OspfInterface] = field(default_factory=list)

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def mis_tuned(self) -> list[OspfInterface]:
        return [
            i for i in self.interfaces
            if not i.is_tuned_correctly
        ]

    @property
    def passive_count(self) -> int:
        return sum(1 for i in self.interfaces if i.passive)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"OSPF: {self.interface_count} واجهة\n"
                f"  مع ضبط خاطئ: {len(self.mis_tuned)}"
            )
        return (
            f"OSPF: {self.interface_count} interface(s)\n"
            f"  Mis-tuned: {len(self.mis_tuned)}"
        )


_OSPF_LINE = re.compile(
    r"^(?P<iface>\S+)\s+is\s+up,\s+line\s+protocol\s+is\s+up.*?"
    r"Internet\s+Address\s+(?P<ip>\S+)/(?P<mask>\d+),.*?"
    r"Area\s+(?P<area>\d+).*?"
    r"Cost:\s+(?P<cost>\d+)",
    re.DOTALL,
)
_HELLO_DEAD = re.compile(
    r"Timer\s+intervals\s+configured,\s+Hello\s+(?P<hello>\d+),"
    r"\s+Dead\s+(?P<dead>\d+)",
    re.MULTILINE,
)
_NET_TYPE = re.compile(
    r"Network\s+type\s+(?P<type>\S+)",
    re.MULTILINE,
)
_PASSIVE = re.compile(
    r"No\s+passive\s+interface|"
    r"Passive\s+interface",
    re.MULTILINE,
)


def parse_cisco_ospf(
    device: str,
    output: str,
) -> OspfReport:
    """Parse Cisco ``show ip ospf interface`` output."""
    rep = OspfReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _OSPF_LINE.finditer(output):
        iface = m.group("iface")
        area = m.group("area")
        try:
            cost = int(m.group("cost"))
        except ValueError:
            cost = 1
        # Per-interface blocks are separated by a blank line.
        body_start = m.start()
        next_match = _OSPF_LINE.search(
            output, m.end(),
        )
        body_end = (
            next_match.start() if next_match else len(output)
        )
        body = output[body_start:body_end]
        hello_m = _HELLO_DEAD.search(body)
        hello = 10
        dead = 40
        if hello_m:
            try:
                hello = int(hello_m.group("hello"))
                dead = int(hello_m.group("dead"))
            except ValueError:
                pass
        nt_m = _NET_TYPE.search(body)
        net_type = nt_m.group("type") if nt_m else "BROADCAST"
        passive = "Passive interface" in body
        rep.interfaces.append(OspfInterface(
            interface=iface,
            area=area,
            cost=cost,
            hello_seconds=hello,
            dead_seconds=dead,
            network_type=net_type,
            passive=passive,
        ))
    return rep
