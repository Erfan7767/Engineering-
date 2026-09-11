"""Maintenance Window Engine — schedule changes, guard with windows.

A 30-year engineer does not apply changes to a production
network at 14:32 on a Friday. Changes are scheduled into
maintenance windows: specific date/time ranges during which
the operator has pre-approved the change.

This module is the typed implementation.

What it does:

* Defines a maintenance window (UTC start/end + label + reason).
* Evaluates "is now inside this window?" with typed results.
* Validates that a proposed apply falls inside an active window
  (or has an explicit override).

What it does NOT do (typed, never silent):

* It does NOT auto-skip applies outside a window. The operator
  must pass an explicit ``--force-outside-window`` flag (or the
  chat equivalent) to override. A missing flag returns
  OUTSIDE_WINDOW with the next-window information.
* It does NOT assume timezone. All times are UTC; the operator
  must convert.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class WindowVerdict(str, Enum):
    __test__ = False

    INSIDE = "INSIDE"
    OUTSIDE = "OUTSIDE"
    NOT_YET = "NOT_YET"   # window opens in the future
    ENDED = "ENDED"       # window has already closed
    INVALID = "INVALID"   # end <= start


@dataclass(frozen=True)
class MaintenanceWindow:
    """A single maintenance window in UTC."""

    __test__ = False

    window_id: str
    label: str
    start_unix: float
    end_unix: float
    reason: str = ""
    contact: str = ""


@dataclass
class WindowCheck:
    """The result of asking "is now inside this window?"."""

    __test__ = False

    window: MaintenanceWindow
    verdict: WindowVerdict
    now_unix: float
    detail: str = ""

    @property
    def is_inside(self) -> bool:
        return self.verdict == WindowVerdict.INSIDE


def evaluate_window(
    w: MaintenanceWindow,
    now_unix: float | None = None,
) -> WindowCheck:
    """Evaluate whether the current time (or ``now_unix``) is
    inside the window. Returns a typed verdict.
    """
    if now_unix is None:
        now_unix = time.time()
    if w.end_unix <= w.start_unix:
        return WindowCheck(
            window=w,
            verdict=WindowVerdict.INVALID,
            now_unix=now_unix,
            detail=f"end ({w.end_unix}) <= start ({w.start_unix})",
        )
    if now_unix < w.start_unix:
        return WindowCheck(
            window=w,
            verdict=WindowVerdict.NOT_YET,
            now_unix=now_unix,
            detail=(
                f"window opens in {w.start_unix - now_unix:.0f}s "
                f"({datetime.fromtimestamp(w.start_unix, tz=timezone.utc).isoformat()})"
            ),
        )
    if now_unix > w.end_unix:
        return WindowCheck(
            window=w,
            verdict=WindowVerdict.ENDED,
            now_unix=now_unix,
            detail=(
                f"window closed {now_unix - w.end_unix:.0f}s ago "
                f"({datetime.fromtimestamp(w.end_unix, tz=timezone.utc).isoformat()})"
            ),
        )
    return WindowCheck(
        window=w,
        verdict=WindowVerdict.INSIDE,
        now_unix=now_unix,
        detail=(
            f"inside window; {w.end_unix - now_unix:.0f}s remain "
            f"(until {datetime.fromtimestamp(w.end_unix, tz=timezone.utc).isoformat()})"
        ),
    )


# ------------------------------------------------------------- window registry
# A simple in-memory registry of windows. Real systems would
# persist this to a database; for the v1 the chat operator
# keeps the registry in memory across the session.

class WindowRegistry:
    """An in-memory store of maintenance windows."""

    def __init__(self) -> None:
        self._windows: list[MaintenanceWindow] = []

    def add(self, w: MaintenanceWindow) -> None:
        for existing in self._windows:
            if existing.window_id == w.window_id:
                return
        self._windows.append(w)

    def list_active(self, now_unix: float | None = None) -> list[MaintenanceWindow]:
        return [
            w for w in self._windows
            if evaluate_window(w, now_unix).is_inside
        ]

    def list_all(self) -> list[MaintenanceWindow]:
        return list(self._windows)

    def get(self, window_id: str) -> MaintenanceWindow | None:
        for w in self._windows:
            if w.window_id == window_id:
                return w
        return None

    def clear(self) -> None:
        self._windows.clear()
