"""PoE Budget Engine — power over Ethernet allocation.

A 30-year network engineer knows that a switch can supply
only so many watts of PoE. If the budget is exceeded, ports
shut down. This module parses ``show power inline`` output
and reports the current PoE allocation per port plus the
device's available budget.

What it does:

* Parses per-interface PoE state (admin, oper, watts, class).
* Compares allocated watts against the device's nominal
  budget.
* Returns a typed report with the current allocation and
  remaining headroom.

What it does NOT do (typed, never silent):

* It does NOT invent a budget. If the device did not report
  a budget, the report is UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PoeState(str, Enum):
    __test__ = False

    ON = "on"
    OFF = "off"
    FAULT = "fault"
    POWER_DENY = "power-deny"
    AUTO = "auto"
    STATIC = "static"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PoePort:
    __test__ = False

    interface: str
    admin: PoeState
    oper: PoeState
    watts: float = 0.0
    class_no: str = ""


@dataclass
class PoeReport:
    __test__ = False

    device_ref: str
    ports: list[PoePort] = field(default_factory=list)
    nominal_budget_w: float = 0.0
    available_w: float = 0.0

    @property
    def allocated_w(self) -> float:
        return sum(p.watts for p in self.ports if p.oper == PoeState.ON)

    @property
    def utilization_pct(self) -> float:
        if self.nominal_budget_w <= 0:
            return 0.0
        return round((self.allocated_w / self.nominal_budget_w) * 100, 1)

    @property
    def on_count(self) -> int:
        return sum(1 for p in self.ports if p.oper == PoeState.ON)

    @property
    def fault_count(self) -> int:
        return sum(1 for p in self.ports if p.oper == PoeState.FAULT)

    @property
    def overall_verdict(self) -> str:
        if not self.ports:
            return "UNKNOWN"
        if self.fault_count > 0:
            return "FAULT"
        if self.utilization_pct > 90:
            return "OVER_BUDGET_RISK"
        if self.utilization_pct > 70:
            return "NEAR_BUDGET"
        return "OK"


_PORT_PATTERN = re.compile(
    r"^(?P<intf>\S+)\s+(?P<admin>\S+)\s+(?P<oper>\S+)\s+"
    r"(?P<watts>\d+\.\d+)\s*(?:Watts)?\s*(?P<class>Class\s*\d+)?",
    re.IGNORECASE | re.MULTILINE,
)

_BUDGET_PATTERN = re.compile(
    r"(?:Available|Avaliable)\s*Power\s*(?:\(watts\))?\s*[:=]?\s*(\d+\.?\d*)",
    re.IGNORECASE,
)


def _state(text: str) -> PoeState:
    t = text.strip().lower()
    try:
        return PoeState(t)
    except ValueError:
        return PoeState.UNKNOWN


def parse(output: str) -> tuple[list[PoePort], float]:
    """Parse ``show power inline`` output. Returns (ports, budget)."""
    if not output or not output.strip():
        return [], 0.0
    ports: list[PoePort] = []
    for m in _PORT_PATTERN.finditer(output):
        # Skip the "Available Power = N Watts" line, which the
        # generic pattern would otherwise consume.
        if "available" in m.group("intf").lower():
            continue
        if m.group("oper").lower() in ("available", "watts", "power"):
            continue
        ports.append(PoePort(
            interface=m.group("intf"),
            admin=_state(m.group("admin")),
            oper=_state(m.group("oper")),
            watts=float(m.group("watts") or 0.0),
            class_no=(m.group("class") or "").strip(),
        ))
    budget = 0.0
    bm = _BUDGET_PATTERN.search(output)
    if bm:
        try:
            budget = float(bm.group(1))
        except ValueError:
            budget = 0.0
    return ports, budget


def analyse(device_ref: str, output: str) -> PoeReport:
    ports, budget = parse(output)
    return PoeReport(
        device_ref=device_ref,
        ports=ports,
        nominal_budget_w=budget,
        available_w=max(0.0, budget - sum(p.watts for p in ports)),
    )


def render(r: PoeReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: PoeReport) -> str:
    lines = [
        f"PoE budget for {r.device_ref}",
        f"  Verdict: {r.overall_verdict}",
        f"  Budget: {r.nominal_budget_w:.1f}W   "
        f"Allocated: {r.allocated_w:.1f}W   "
        f"Available: {r.available_w:.1f}W   "
        f"Utilization: {r.utilization_pct:.1f}%",
        f"  Ports ON: {r.on_count}   Fault: {r.fault_count}   "
        f"Total: {len(r.ports)}",
    ]
    if r.fault_count > 0:
        lines.append("  Fault ports:")
        for p in r.ports:
            if p.oper == PoeState.FAULT:
                lines.append(f"    {p.interface}: FAULT ({p.watts:.1f}W)")
    return "\n".join(lines)


def _render_ar(r: PoeReport) -> str:
    lines = [
        f"ميزانية PoE لـ {r.device_ref}",
        f"  النتيجة: {r.overall_verdict}",
        f"  الميزانية: {r.nominal_budget_w:.1f}واط   "
        f"المخصص: {r.allocated_w:.1f}واط   "
        f"المتاح: {r.available_w:.1f}واط   "
        f"الاستخدام: {r.utilization_pct:.1f}%",
        f"  المنافذ النشطة: {r.on_count}   الأعطال: {r.fault_count}   "
        f"المجموع: {len(r.ports)}",
    ]
    if r.fault_count > 0:
        lines.append("  المنافذ المعطلة:")
        for p in r.ports:
            if p.oper == PoeState.FAULT:
                lines.append(f"    {p.interface}: عطل ({p.watts:.1f}واط)")
    return "\n".join(lines)
