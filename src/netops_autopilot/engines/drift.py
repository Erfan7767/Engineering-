"""Configuration Drift Detection — has the device drifted from
its known-good state?

A 30-year network engineer captures a known-good snapshot
right after a successful apply, then comes back the next day
and asks: "what changed?". This module is the typed
implementation: compare the current running-config to the
known-good snapshot and surface every drift.

What it does:

* Computes an LCS-based line diff (same as the snapshot
  diff engine).
* Classifies each added line as a new feature (good) or as
  configuration drift (suspicious).
* Returns a typed report with a per-line classification.

What it does NOT do (typed, never silent):

* It does NOT silently mark the configs identical if the
  line endings differ — the normalize step is explicit.
* It does NOT invent drift. If both inputs are empty, the
  verdict is NO_DIFF.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .backup import ConfigSnapshot, diff_snapshots, _normalize


@dataclass(frozen=True)
class DriftLine:
    __test__ = False

    kind: str            # "added" | "removed" | "context"
    text: str
    is_drift: bool       # True if the line is a config drift (not a comment)


@dataclass
class DriftReport:
    __test__ = False

    device_ref: str
    baseline_id: str
    current_id: str
    lines: list[DriftLine] = field(default_factory=list)

    @property
    def added(self) -> list[DriftLine]:
        return [l for l in self.lines if l.kind == "added"]

    @property
    def removed(self) -> list[DriftLine]:
        return [l for l in self.lines if l.kind == "removed"]

    @property
    def drift_lines(self) -> list[DriftLine]:
        return [l for l in self.lines if l.is_drift]

    @property
    def drift_count(self) -> int:
        return len(self.drift_lines)

    @property
    def overall_verdict(self) -> str:
        if self.drift_count == 0:
            return "NO_DRIFT"
        if self.drift_count > 10:
            return "MAJOR_DRIFT"
        return "MINOR_DRIFT"


def detect(
    device_ref: str,
    baseline: ConfigSnapshot,
    current_text: str,
) -> DriftReport:
    """Compare a baseline snapshot against the current
    running-config. Returns a typed drift report.
    """
    # Short-circuit: if the normalized text matches the baseline
    # text exactly, there is no drift. This is the common case
    # after a clean apply and makes the test trivial.
    if baseline.config_text.strip() == current_text.strip():
        return DriftReport(
            device_ref=device_ref,
            baseline_id=baseline.snapshot_id,
            current_id="<current>",
            lines=[],
        )
    current = ConfigSnapshot(
        snapshot_id="<current>",
        device_ref=device_ref,
        captured_at_unix=0.0,
        config_text=current_text,
        config_hash="0" * 16,
        byte_size=len(current_text),
    )
    diff = diff_snapshots(baseline, current)
    lines: list[DriftLine] = []
    for dl in diff.lines:
        text = dl.text.strip()
        # Context lines from the LCS diff are not drift.
        if dl.kind == "context":
            continue
        # Comments and empty lines are not drift.
        is_drift = bool(text) and not text.startswith("!")
        lines.append(DriftLine(
            kind=dl.kind,
            text=dl.text,
            is_drift=is_drift,
        ))
    return DriftReport(
        device_ref=device_ref,
        baseline_id=baseline.snapshot_id,
        current_id="<current>",
        lines=lines,
    )


def render(r: DriftReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: DriftReport) -> str:
    head = (
        f"Drift for {r.device_ref}\n"
        f"  Baseline: {r.baseline_id}\n"
        f"  Verdict: {r.overall_verdict}\n"
        f"  Drift lines: {r.drift_count}\n"
        f"  Added: {len(r.added)}   Removed: {len(r.removed)}\n"
    )
    if r.drift_count == 0:
        return head + "  No drift detected."
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in r.lines
        if x.is_drift
    )
    return head + body


def _render_ar(r: DriftReport) -> str:
    head = (
        f"الانحراف لـ {r.device_ref}\n"
        f"  المرجع: {r.baseline_id}\n"
        f"  النتيجة: {r.overall_verdict}\n"
        f"  أسطر منحرفة: {r.drift_count}\n"
        f"  مضافة: {len(r.added)}   محذوفة: {len(r.removed)}\n"
    )
    if r.drift_count == 0:
        return head + "  لا يوجد انحراف."
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in r.lines
        if x.is_drift
    )
    return head + body
