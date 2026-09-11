"""Capacity Planner — predict when a network runs out of room.

A 30-year engineer keeps a running forecast: "with current
growth, port density on the access switches will be at 90%
in 11 months". This module is the typed implementation: a
linear projection from a current sample + a monthly growth
rate, with explicit ``days_until_threshold`` for every
metric.

Design contract:

* **Deterministic** — given a :class:`CapacitySample` and a
  growth rate, every forecast is reproducible.
* **Typed** — every metric has a threshold and a typed
  :class:`CapacityVerdict`.
* **Bilingual** — rendering in English or Arabic.
* **No hallucination** — if the current sample is below the
  threshold, the verdict is OK with days_until = None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CapacityVerdict(str, Enum):
    __test__ = False

    OK = "OK"                     # below threshold
    APPROACHING = "APPROACHING"   # within 90 days
    EXHAUSTED = "EXHAUSTED"       # at or above threshold
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CapacitySample:
    __test__ = False

    metric: str              # "ports", "poe_watts", "vlan_count", etc.
    current: float
    capacity: float
    monthly_growth: float    # absolute units per month
    threshold_pct: float = 90.0

    @property
    def utilization_pct(self) -> float:
        if self.capacity <= 0:
            return 0.0
        return (self.current / self.capacity) * 100

    @property
    def threshold_value(self) -> float:
        return (self.threshold_pct / 100.0) * self.capacity


@dataclass
class CapacityForecast:
    __test__ = False

    sample: CapacitySample
    days_until_threshold: int | None
    verdict: CapacityVerdict
    projected_in_12mo: float

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"[{self.verdict.value}] {self.sample.metric}\n"
                f"   الحالي: {self.sample.current:.1f} / "
                f"{self.sample.capacity:.1f} "
                f"({self.sample.utilization_pct:.1f}%)\n"
                f"   النمو: {self.sample.monthly_growth}/شهر\n"
                + (
                    f"   سيتجاوز خلال: {self.days_until_threshold} يوم"
                    if self.days_until_threshold is not None
                    else "   تحت الحد"
                )
            )
        return (
            f"[{self.verdict.value}] {self.sample.metric}\n"
            f"   Current: {self.sample.current:.1f} / "
            f"{self.sample.capacity:.1f} "
            f"({self.sample.utilization_pct:.1f}%)\n"
            f"   Growth: {self.sample.monthly_growth}/month\n"
            + (
                f"   Days until threshold: {self.days_until_threshold}"
                if self.days_until_threshold is not None
                else "   Below threshold"
            )
        )


@dataclass
class CapacityReport:
    __test__ = False

    forecasts: list[CapacityForecast] = field(default_factory=list)

    @property
    def critical(self) -> list[CapacityForecast]:
        return [
            f for f in self.forecasts
            if f.verdict == CapacityVerdict.EXHAUSTED
        ]

    @property
    def approaching(self) -> list[CapacityForecast]:
        return [
            f for f in self.forecasts
            if f.verdict == CapacityVerdict.APPROACHING
        ]

    @property
    def overall_verdict(self) -> str:
        if self.critical:
            return "EXHAUSTED"
        if self.approaching:
            return "APPROACHING"
        if self.forecasts:
            return "OK"
        return "UNKNOWN"

    def render(self, lang: str = "en") -> str:
        if not self.forecasts:
            return (
                "No capacity samples — nothing to forecast."
                if lang == "en"
                else "لا توجد عينات سعة — لا شيء للتنبؤ."
            )
        head = (
            f"Capacity forecast: {self.overall_verdict}"
            if lang == "en"
            else f"تنبؤ السعة: {self.overall_verdict}"
        )
        body = "\n".join(
            f.render(lang=lang) for f in self.forecasts
        )
        return head + "\n\n" + body


def forecast_one(sample: CapacitySample) -> CapacityForecast:
    """Project a single :class:`CapacitySample` forward."""
    if sample.capacity <= 0:
        return CapacityForecast(
            sample=sample,
            days_until_threshold=None,
            verdict=CapacityVerdict.UNKNOWN,
            projected_in_12mo=sample.current,
        )
    util = sample.utilization_pct
    if util >= sample.threshold_pct:
        return CapacityForecast(
            sample=sample,
            days_until_threshold=0,
            verdict=CapacityVerdict.EXHAUSTED,
            projected_in_12mo=sample.current + sample.monthly_growth * 12,
        )
    # Days until threshold_value: solve current + (days/30) * growth >= threshold_value
    if sample.monthly_growth <= 0:
        days = None
    else:
        remaining = sample.threshold_value - sample.current
        # months_until = remaining / monthly_growth
        # days_until = months_until * 30
        months = remaining / sample.monthly_growth
        days = int(round(months * 30))
    if days is not None and days <= 90:
        verdict = CapacityVerdict.APPROACHING
    elif days is not None and days <= 0:
        verdict = CapacityVerdict.EXHAUSTED
    else:
        verdict = CapacityVerdict.OK
    return CapacityForecast(
        sample=sample,
        days_until_threshold=days,
        verdict=verdict,
        projected_in_12mo=sample.current + sample.monthly_growth * 12,
    )


def forecast(samples: list[CapacitySample]) -> CapacityReport:
    """Forecast a list of samples."""
    rep = CapacityReport()
    for s in samples:
        rep.forecasts.append(forecast_one(s))
    return rep
