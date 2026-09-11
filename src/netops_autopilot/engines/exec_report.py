"""Executive Report Engine — daily / weekly summaries for the CIO.

A 30-year engineer keeps management informed with a
one-page weekly summary: device count, change count,
anomalies, EOL warnings, capacity outlook. This module is
the typed implementation: build a typed
:class:`ExecutiveReport` from a set of inputs.

Design contract:

* **Typed inputs** — :class:`ReportInputs` carries the
  numbers; the engine never invents them.
* **Bilingual** — rendering in English or Arabic.
* **Markdown-ready** — output is plain text suitable for
  Markdown rendering.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ReportInputs:
    __test__ = False

    device_count: int = 0
    reachable_count: int = 0
    change_count: int = 0
    anomaly_count: int = 0
    eol_warning_count: int = 0
    capacity_alerts: int = 0
    evidence_count: int = 0
    period_label: str = "this week"
    period_label_ar: str = "هذا الأسبوع"


@dataclass
class ExecutiveReport:
    __test__ = False

    inputs: ReportInputs
    sections: list[str] = field(default_factory=list)
    sections_ar: list[str] = field(default_factory=list)

    @property
    def overall_verdict(self) -> str:
        if self.inputs.anomaly_count > 0:
            return "ATTENTION_REQUIRED"
        if self.inputs.eol_warning_count > 0:
            return "PLAN_REFRESH"
        if self.inputs.capacity_alerts > 0:
            return "PLAN_CAPACITY"
        return "STABLE"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"# ملخص تنفيذي ({self.inputs.period_label_ar})\n\n"
                + "\n".join(self.sections_ar)
            )
        return (
            f"# Executive summary ({self.inputs.period_label})\n\n"
            + "\n".join(self.sections)
        )


def build(
    inputs: ReportInputs,
    lang: str = "en",
) -> ExecutiveReport:
    """Build an :class:`ExecutiveReport` from typed inputs."""
    rep = ExecutiveReport(inputs=inputs)
    if lang == "ar":
        rep.sections_ar = [
            f"## الأجهزة\n"
            f"- الإجمالي: {inputs.device_count}\n"
            f"- القابل للوصول: {inputs.reachable_count}",
            f"## التغييرات\n"
            f"- تم تطبيق {inputs.change_count} تغيير",
            f"## الشذوذ\n"
            f"- {inputs.anomaly_count} مشكلة في الطوبولوجيا",
            f"## دورة الحياة\n"
            f"- {inputs.eol_warning_count} جهاز يقترب من نهاية الدعم",
            f"## السعة\n"
            f"- {inputs.capacity_alerts} تنبيهات سعة",
            f"## التدقيق\n"
            f"- {inputs.evidence_count} حدث مسجل في السجل",
            f"## الخلاصة\n"
            f"- الحالة العامة: **{rep.overall_verdict}**",
        ]
    rep.sections = [
        f"## Devices\n"
        f"- Total: {inputs.device_count}\n"
        f"- Reachable: {inputs.reachable_count}",
        f"## Changes\n"
        f"- {inputs.change_count} change(s) applied",
        f"## Anomalies\n"
        f"- {inputs.anomaly_count} topology anomaly/finding",
        f"## Lifecycle\n"
        f"- {inputs.eol_warning_count} device(s) approaching EOL",
        f"## Capacity\n"
        f"- {inputs.capacity_alerts} capacity alert(s)",
        f"## Audit\n"
        f"- {inputs.evidence_count} signed event(s) in the ledger",
        f"## Bottom line\n"
        f"- Overall: **{rep.overall_verdict}**",
    ]
    return rep
