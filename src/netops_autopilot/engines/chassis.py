"""Chassis / Stack Health — modular switches and stacks.

A 30-year engineer keeps an eye on stack/cable/modular
chassis health: which members are in the stack, which
slots are populated, which fans are failing.

This module is the typed implementation: parse Cisco
``show switch`` / ``show module`` / ``show environment``
output, surface typed :class:`StackMember` and
:class:`ChassisModule` records and a typed
:class:`ChassisReport` with findings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class StackMember:
    __test__ = False

    member_id: int
    role: str = ""            # "Active" / "Standby" / "Member"
    mac: str = ""
    state: str = ""
    priority: int = 0


@dataclass(frozen=True)
class ChassisModule:
    __test__ = False

    slot: int
    type: str = ""
    serial: str = ""
    state: str = ""           # ok / faulty / missing
    ports: int = 0


@dataclass
class ChassisReport:
    __test__ = False

    device: str
    stack: list[StackMember] = field(default_factory=list)
    modules: list[ChassisModule] = field(default_factory=list)

    @property
    def stack_size(self) -> int:
        return len(self.stack)

    @property
    def active_member(self) -> StackMember | None:
        for m in self.stack:
            if m.role.lower() == "active":
                return m
        return None

    @property
    def faulty_modules(self) -> list[ChassisModule]:
        return [
            m for m in self.modules
            if m.state.lower() in ("faulty", "missing", "down")
        ]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"Chassis: {self.stack_size} عضو، "
                f"{len(self.faulty_modules)} معطّل"
            )
        return (
            f"Chassis: {self.stack_size} stack member(s), "
            f"{len(self.faulty_modules)} faulty"
        )


_STACK_LINE = re.compile(
    r"^(?P<id>\d+)\s+(?P<role>\S+)\s+(?P<mac>[0-9a-fA-F:.]+)\s+"
    r"(?P<state>\S+)\s+(?P<prio>\d+)\s*$",
    re.MULTILINE,
)
_MODULE_LINE = re.compile(
    r"^(?P<slot>\d+)\s+(?P<type>\S+)\s+(?P<serial>\S+)\s+"
    r"(?P<state>\S+)\s+(?P<ports>\d+)",
    re.MULTILINE,
)


def parse_stack(
    device: str,
    output: str,
) -> ChassisReport:
    """Parse ``show switch`` summary."""
    rep = ChassisReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _STACK_LINE.finditer(output):
        try:
            mid = int(m.group("id"))
            prio = int(m.group("prio"))
        except ValueError:
            mid = 0
            prio = 0
        rep.stack.append(StackMember(
            member_id=mid,
            role=m.group("role"),
            mac=m.group("mac"),
            state=m.group("state"),
            priority=prio,
        ))
    return rep


def parse_modules(
    device: str,
    output: str,
) -> ChassisReport:
    """Parse ``show module`` summary."""
    rep = ChassisReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _MODULE_LINE.finditer(output):
        try:
            slot = int(m.group("slot"))
            ports = int(m.group("ports"))
        except ValueError:
            slot = 0
            ports = 0
        rep.modules.append(ChassisModule(
            slot=slot,
            type=m.group("type"),
            serial=m.group("serial"),
            state=m.group("state"),
            ports=ports,
        ))
    return rep
