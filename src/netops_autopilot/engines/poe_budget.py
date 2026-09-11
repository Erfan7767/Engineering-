"""Power Budget Calculator — PoE class + budget allocation.

A 30-year engineer knows PoE Class math: Class 0 = 15.4W,
Class 4 = 30W, with 90W per port for Cisco UPoE+. This
module is the typed implementation: take a list of
:class:`PoePoweredDevice` records and a switch budget,
surface a typed :class:`PowerBudgetReport`.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PoeClass(str, Enum):
    __test__ = False

    CLASS_0 = "0"
    CLASS_1 = "1"
    CLASS_2 = "2"
    CLASS_3 = "3"
    CLASS_4 = "4"
    CLASS_5 = "5"     # Type 1
    CLASS_6 = "6"     # Type 2
    CLASS_7 = "7"     # Type 3
    CLASS_8 = "8"     # Type 4 / UPoE+
    UNKNOWN = "unknown"


_CLASS_WATTS = {
    PoeClass.CLASS_0: 15.4,
    PoeClass.CLASS_1: 4.0,
    PoeClass.CLASS_2: 7.0,
    PoeClass.CLASS_3: 15.4,
    PoeClass.CLASS_4: 30.0,
    PoeClass.CLASS_5: 45.0,
    PoeClass.CLASS_6: 60.0,
    PoeClass.CLASS_7: 75.0,
    PoeClass.CLASS_8: 90.0,
}


@dataclass(frozen=True)
class PoePoweredDevice:
    __test__ = False

    port: str
    device_id: str = ""
    poe_class: PoeClass = PoeClass.UNKNOWN
    watts: float = 0.0

    @property
    def requested_watts(self) -> float:
        if self.watts > 0:
            return self.watts
        return _CLASS_WATTS.get(self.poe_class, 15.4)


@dataclass
class PowerBudgetReport:
    __test__ = False

    device: str
    total_budget_watts: float
    devices: list[PoePoweredDevice] = field(default_factory=list)

    @property
    def allocated_watts(self) -> float:
        return sum(d.requested_watts for d in self.devices)

    @property
    def remaining_watts(self) -> float:
        return max(
            0.0,
            self.total_budget_watts - self.allocated_watts,
        )

    @property
    def utilization_pct(self) -> float:
        if self.total_budget_watts <= 0:
            return 0.0
        return min(
            100.0,
            (self.allocated_watts / self.total_budget_watts) * 100.0,
        )

    @property
    def is_over_budget(self) -> bool:
        return self.allocated_watts > self.total_budget_watts

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"PoE: {self.allocated_watts:.1f}/{self.total_budget_watts:.0f}W "
                f"({self.utilization_pct:.1f}%)، "
                f"{'تجاوز' if self.is_over_budget else 'متبقي'} "
                f"{self.remaining_watts:.1f}W"
            )
        return (
            f"PoE: {self.allocated_watts:.1f}/{self.total_budget_watts:.0f}W "
            f"({self.utilization_pct:.1f}%), "
            f"{'OVER' if self.is_over_budget else 'remaining'} "
            f"{self.remaining_watts:.1f}W"
        )
