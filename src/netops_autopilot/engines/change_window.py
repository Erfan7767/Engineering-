"""Change Window Scheduler — find a safe time to apply a change.

A 30-year engineer knows: never reload a router at 14:00 on
a Tuesday. Use the maintenance window. This module is the
typed implementation: given a planned change and a list of
candidate windows, pick the best one (least impact, latest
acceptable, most operator coverage).

Design contract:

* **Typed windows** — :class:`ChangeWindow` with
  start / end / reason / impact_estimate.
* **Best-fit selection** — :func:`pick_best_window` returns
  the window with the lowest impact estimate that still
  covers the required duration.
* **No hallucination** — if no window fits, the result is
  typed ``NO_FIT``, not "pick one anyway".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class WindowImpact(str, Enum):
    __test__ = False

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class WindowOutcome(str, Enum):
    __test__ = False

    PICKED = "PICKED"
    NO_FIT = "NO_FIT"
    INSUFFICIENT_DURATION = "INSUFFICIENT_DURATION"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class ChangeWindow:
    __test__ = False

    window_id: str
    start_unix: float
    end_unix: float
    impact: WindowImpact
    reason: str = ""
    operators: tuple[str, ...] = ()

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end_unix - self.start_unix)

    def covers(self, required_s: float) -> bool:
        return self.duration_s >= required_s


@dataclass(frozen=True)
class PlannedChange:
    __test__ = False

    change_id: str
    estimated_duration_s: float
    requires_window_impact: WindowImpact = WindowImpact.LOW
    rationale: str = ""


@dataclass
class WindowSelection:
    __test__ = False

    change: PlannedChange
    picked: ChangeWindow | None = None
    outcome: WindowOutcome = WindowOutcome.NO_FIT
    candidates: list[ChangeWindow] = field(default_factory=list)
    reason: str = ""

    def render(self, lang: str = "en") -> str:
        head = (
            f"Window selection for {self.change.change_id}"
            if lang == "en"
            else f"اختيار النافذة لـ {self.change.change_id}"
        )
        if lang == "ar":
            verdict_map = {
                WindowOutcome.PICKED: "تم اختيار نافذة",
                WindowOutcome.NO_FIT: "لا توجد نافذة مناسبة",
                WindowOutcome.INSUFFICIENT_DURATION:
                    "النوافذ المتاحة أقصر من اللازم",
                WindowOutcome.CONFLICT: "تعارض مع نوافذ أخرى",
            }
            verdict = verdict_map.get(self.outcome, "?")
            return (
                f"{head}\n"
                f"  النتيجة: {verdict}\n"
                f"  المرشحون: {len(self.candidates)}\n"
                + (
                    f"  المختار: {self.picked.window_id} "
                    f"({self.picked.start_unix}→{self.picked.end_unix})\n"
                    if self.picked else ""
                )
                + (
                    f"  السبب: {self.reason}" if self.reason else ""
                )
            )
        verdict_map = {
            WindowOutcome.PICKED: "Window picked",
            WindowOutcome.NO_FIT: "No fit",
            WindowOutcome.INSUFFICIENT_DURATION:
                "Windows too short",
            WindowOutcome.CONFLICT: "Conflict",
        }
        verdict = verdict_map.get(self.outcome, "?")
        return (
            f"{head}\n"
            f"  Outcome: {verdict}\n"
            f"  Candidates: {len(self.candidates)}\n"
            + (
                f"  Picked: {self.picked.window_id} "
                f"({self.picked.start_unix}→{self.picked.end_unix})\n"
                if self.picked else ""
            )
            + (
                f"  Reason: {self.reason}" if self.reason else ""
            )
        )


def pick_best_window(
    change: PlannedChange,
    windows: list[ChangeWindow],
    *,
    now_unix: float | None = None,
) -> WindowSelection:
    """Pick the lowest-impact window that fits and is in the
    future. Ties are broken by the latest start time."""
    if not windows:
        return WindowSelection(
            change=change,
            outcome=WindowOutcome.NO_FIT,
            reason="no windows defined",
        )
    now = now_unix if now_unix is not None else _now()
    impact_order = [
        WindowImpact.LOW, WindowImpact.MEDIUM, WindowImpact.HIGH,
    ]
    future = [w for w in windows if w.end_unix > now]
    if not future:
        return WindowSelection(
            change=change,
            outcome=WindowOutcome.NO_FIT,
            candidates=list(windows),
            reason="all windows are in the past",
        )
    fitting = [w for w in future if w.covers(change.estimated_duration_s)]
    if not fitting:
        return WindowSelection(
            change=change,
            outcome=WindowOutcome.INSUFFICIENT_DURATION,
            candidates=list(windows),
            reason=(
                f"required {change.estimated_duration_s}s, "
                f"max window is "
                f"{max(w.duration_s for w in future)}s"
            ),
        )
    # Filter by impact: only pick a window whose impact <= required.
    required_idx = impact_order.index(change.requires_window_impact)
    eligible = [
        w for w in fitting
        if impact_order.index(w.impact) <= required_idx
    ]
    if not eligible:
        return WindowSelection(
            change=change,
            outcome=WindowOutcome.CONFLICT,
            candidates=list(windows),
            reason=(
                "no window has impact ≤ "
                f"{change.requires_window_impact.value}"
            ),
        )
    # Sort: lowest impact, then latest start.
    eligible.sort(
        key=lambda w: (
            impact_order.index(w.impact),
            -w.start_unix,
        )
    )
    picked = eligible[0]
    return WindowSelection(
        change=change,
        picked=picked,
        outcome=WindowOutcome.PICKED,
        candidates=list(windows),
        reason=(
            f"lowest impact at {picked.impact.value}, "
            f"latest start among eligible"
        ),
    )


def _now() -> float:
    import time
    return time.time()
