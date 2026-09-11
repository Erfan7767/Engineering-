"""Performance Baseline & Anomaly Detection — what's normal for this network?

A 30-year engineer keeps a running mental baseline: "this
uplink normally does 200-300 Mbps at peak; 800 Mbps means
something is wrong." This module is the typed implementation:
record a baseline, then check new samples against it.

The detector uses a robust z-score (median + MAD) so a few
outliers don't poison the model — exactly what a senior
engineer does by feel.

Design contract:

* **Typed metrics** — every baseline is a
  :class:`BaselineMetric` with a median and a MAD-based
  threshold.
* **No LLM** — every verdict is a typed
  :class:`AnomalyVerdict` (NORMAL / ELEVATED / ANOMALOUS /
  INSUFFICIENT_DATA).
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from enum import Enum


class AnomalyVerdict(str, Enum):
    __test__ = False

    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    ANOMALOUS = "ANOMALOUS"


@dataclass(frozen=True)
class BaselineMetric:
    __test__ = False

    name: str
    median: float
    mad: float             # median absolute deviation
    samples: tuple[float, ...]

    @property
    def threshold_anomaly(self) -> float:
        return self.median + 3 * self.mad

    @property
    def threshold_elevated(self) -> float:
        return self.median + 2 * self.mad


@dataclass(frozen=True)
class BaselineSample:
    __test__ = False

    metric: str
    value: float


@dataclass
class AnomalyFinding:
    __test__ = False

    metric: str
    value: float
    baseline_median: float
    baseline_mad: float
    verdict: AnomalyVerdict

    def render(self, lang: str = "en") -> str:
        ratio = (
            "?" if self.baseline_median == 0
            else self.value / self.baseline_median
        )
        if lang == "ar":
            return (
                f"[{self.verdict.value}] {self.metric}\n"
                f"   القيمة: {self.value:.2f}  "
                f"(الوسيط: {self.baseline_median:.2f}, "
                f"×{ratio:.2f})\n"
                f"   MAD: {self.baseline_mad:.2f}"
            )
        return (
            f"[{self.verdict.value}] {self.metric}\n"
            f"   Value: {self.value:.2f}  "
            f"(median: {self.baseline_median:.2f}, "
            f"×{ratio:.2f})\n"
            f"   MAD: {self.baseline_mad:.2f}"
        )


@dataclass
class AnomalyReport:
    __test__ = False

    findings: list[AnomalyFinding] = field(default_factory=list)

    @property
    def anomalous(self) -> list[AnomalyFinding]:
        return [
            f for f in self.findings
            if f.verdict == AnomalyVerdict.ANOMALOUS
        ]

    @property
    def overall_verdict(self) -> str:
        if any(
            f.verdict == AnomalyVerdict.INSUFFICIENT_DATA
            for f in self.findings
        ):
            return "INSUFFICIENT_DATA"
        if self.anomalous:
            return "ANOMALY_DETECTED"
        if any(
            f.verdict == AnomalyVerdict.ELEVATED
            for f in self.findings
        ):
            return "ELEVATED"
        return "NORMAL"

    def render(self, lang: str = "en") -> str:
        if not self.findings:
            return (
                "No samples to compare."
                if lang == "en"
                else "لا توجد عينات للمقارنة."
            )
        head = (
            f"Performance baseline check: {self.overall_verdict}"
            if lang == "en"
            else f"فحص الأداء: {self.overall_verdict}"
        )
        body = "\n".join(
            f.render(lang=lang) for f in self.findings
        )
        return head + "\n\n" + body


def build_baseline(samples: list[float], name: str) -> BaselineMetric:
    """Compute median + MAD for a sample window."""
    if not samples:
        return BaselineMetric(
            name=name, median=0.0, mad=0.0, samples=(),
        )
    median = statistics.median(samples)
    mad = statistics.median(
        [abs(x - median) for x in samples]
    )
    return BaselineMetric(
        name=name,
        median=float(median),
        mad=float(mad),
        samples=tuple(samples),
    )


def check(
    baselines: dict[str, BaselineMetric],
    samples: list[BaselineSample],
) -> AnomalyReport:
    """Check each :class:`BaselineSample` against its baseline."""
    rep = AnomalyReport()
    for s in samples:
        baseline = baselines.get(s.metric)
        if baseline is None or baseline.mad == 0:
            # Without a baseline / with zero MAD we can only
            # say we have insufficient data.
            rep.findings.append(AnomalyFinding(
                metric=s.metric,
                value=s.value,
                baseline_median=baseline.median if baseline else 0.0,
                baseline_mad=baseline.mad if baseline else 0.0,
                verdict=AnomalyVerdict.INSUFFICIENT_DATA,
            ))
            continue
        delta = abs(s.value - baseline.median)
        z_like = delta / baseline.mad
        if s.value >= baseline.threshold_anomaly:
            verdict = AnomalyVerdict.ANOMALOUS
        elif s.value >= baseline.threshold_elevated:
            verdict = AnomalyVerdict.ELEVATED
        else:
            verdict = AnomalyVerdict.NORMAL
        rep.findings.append(AnomalyFinding(
            metric=s.metric,
            value=s.value,
            baseline_median=baseline.median,
            baseline_mad=baseline.mad,
            verdict=verdict,
        ))
    return rep
