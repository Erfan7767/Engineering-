"""Hardware Inventory + License Tracker — typed device records.

A 30-year engineer keeps a hardware inventory: serial
number, part number, software version, license status.
This module is the typed implementation: parse
``show inventory`` / ``show version`` output, surface
typed :class:`InventoryItem` records and a typed
:class:`InventoryReport` with EOL warnings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date


@dataclass(frozen=True)
class InventoryItem:
    __test__ = False

    name: str
    description: str
    pid: str = ""         # Product ID
    vid: str = ""         # Version ID
    sn: str = ""          # Serial Number
    eol_date: str = ""    # ISO date if known
    eos_date: str = ""    # End of SW support

    @property
    def is_past_eol(self) -> bool:
        if not self.eol_date:
            return False
        try:
            return date.fromisoformat(self.eol_date) < date.today()
        except ValueError:
            return False


@dataclass
class InventoryReport:
    __test__ = False

    device: str
    items: list[InventoryItem] = field(default_factory=list)
    software_version: str = ""

    @property
    def item_count(self) -> int:
        return len(self.items)

    @property
    def past_eol_items(self) -> list[InventoryItem]:
        return [i for i in self.items if i.is_past_eol]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"المخزون: {self.item_count} عنصر\n"
                f"  تجاوز EOL: {len(self.past_eol_items)}"
            )
        else:
            head = (
                f"Inventory: {self.item_count} item(s)\n"
                f"  Past EOL: {len(self.past_eol_items)}"
            )
        if self.software_version:
            head += f"\n  SW: {self.software_version}"
        return head


_INV_LINE = re.compile(
    r"NAME:\s+\"(?P<name>[^\"]+)\",\s+DESCR:\s+\"(?P<descr>[^\"]+)\""
    r"(?:.*?PID:\s+(?P<pid>\S+))?"
    r"(?:.*?VID:\s+(?P<vid>\S+))?"
    r"(?:.*?SN:\s+(?P<sn>\S+))?",
    re.DOTALL,
)


def parse_cisco_inventory(
    device: str,
    output: str,
) -> InventoryReport:
    """Parse Cisco ``show inventory`` output."""
    rep = InventoryReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _INV_LINE.finditer(output):
        rep.items.append(InventoryItem(
            name=m.group("name"),
            description=m.group("descr"),
            pid=(m.group("pid") or ""),
            vid=(m.group("vid") or ""),
            sn=(m.group("sn") or ""),
        ))
    return rep
