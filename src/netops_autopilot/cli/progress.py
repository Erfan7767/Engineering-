"""Live progress reporter — high-fidelity, deterministic, audit-friendly.

Built by Meta-Agent 3 (Engine Enhancer).

The :class:`ProgressReporter` provides a real-time view of long-running
operations (discovery, design, render, execution) with:

* **Per-step timing** — every phase records start/end and a deterministic
  duration (using the injected clock; no wall-clock dependence in tests).
* **Cancelable** — ``cancel()`` flips an internal flag the worker thread
  polls at safe points. The flag is the *only* cross-thread state.
* **Failure integration** — every phase catches :class:`Failure` and stores
  the typed cause so the report is honest, not "PASS".
* **Deterministic IDs** — every step is named by an idempotent ID derived
  from the run + phase + device, so logs/reports are replayable.

This module is purely a *reporter* — it never mutates engine state. The
engine calls :meth:`begin`, :meth:`update`, :meth:`end` (or ``:meth:`fail`).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Protocol


class StepStatus(str, Enum):
    """The five states a step can be in."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    OK = "OK"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Clock(Protocol):
    def __call__(self) -> float: ...


class _WallClock:
    def __call__(self) -> float:
        return time.monotonic()


@dataclass
class Step:
    """A single tracked operation (a phase, a device crawl, a command)."""
    id: str
    name: str
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    detail: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)

    @property
    def duration_s(self) -> Optional[float]:
        if self.started_at is None or self.finished_at is None:
            return None
        return max(0.0, self.finished_at - self.started_at)


@dataclass
class ProgressSnapshot:
    """A point-in-time snapshot of a run's progress."""
    run_id: str
    total_steps: int
    completed_steps: int
    failed_steps: int
    running_step: Optional[str]
    elapsed_s: float
    steps: list[Step]
    cancelled: bool


class ProgressReporter:
    """Thread-safe progress reporter for the orchestrator.

    Usage::

        reporter = ProgressReporter(run_id="run-123")
        sid = reporter.begin("BOND", "Confirm physical binding")
        try:
            # ... do work ...
            reporter.end(sid, evidence_ids=["e1"])
        except Failure as exc:
            reporter.fail(sid, "; ".join(exc.causes))
    """

    def __init__(self, run_id: str, *, clock: Optional[Clock] = None) -> None:
        self._run_id = run_id
        self._clock = clock or _WallClock()
        self._steps: dict[str, Step] = {}
        self._lock = threading.Lock()
        self._cancelled = False
        self._started_at: Optional[float] = None
        self._listeners: list[Callable[[ProgressSnapshot], None]] = []

    # ---- subscription ----

    def subscribe(self, listener: Callable[[ProgressSnapshot], None]) -> None:
        """Register a listener to receive snapshots on every state change."""
        with self._lock:
            self._listeners.append(listener)

    def unsubscribe(self, listener: Callable[[ProgressSnapshot], None]) -> None:
        with self._lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    def _notify(self) -> None:
        snap = self.snapshot()
        for listener in list(self._listeners):
            try:
                listener(snap)
            except Exception:  # noqa: BLE001 — listeners must not break the reporter
                pass

    # ---- cancellation ----

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        """Request cancellation. Idempotent."""
        with self._lock:
            if not self._cancelled:
                self._cancelled = True
        self._notify()

    def _is_cancelled(self) -> bool:
        return self._cancelled

    # ---- step lifecycle ----

    def begin(self, phase: str, name: str, *, step_id: Optional[str] = None) -> str:
        """Start a step. Returns the step ID."""
        sid = step_id or f"{self._run_id}:{phase}:{name}"
        now = self._clock()
        with self._lock:
            if self._started_at is None:
                self._started_at = now
            step = Step(id=sid, name=name, status=StepStatus.RUNNING, started_at=now)
            self._steps[sid] = step
        self._notify()
        return sid

    def update(
        self,
        step_id: str,
        *,
        detail: Optional[str] = None,
        evidence_ids: Optional[list[str]] = None,
        counters: Optional[dict[str, int]] = None,
    ) -> None:
        """Update a running step's metadata without changing its status."""
        with self._lock:
            step = self._steps.get(step_id)
            if step is None or step.status is not StepStatus.RUNNING:
                return
            if detail is not None:
                step.detail = detail
            if evidence_ids is not None:
                step.evidence_ids = list(evidence_ids)
            if counters is not None:
                step.counters = dict(counters)
        self._notify()

    def end(
        self,
        step_id: str,
        *,
        detail: Optional[str] = None,
        evidence_ids: Optional[list[str]] = None,
    ) -> None:
        """Mark a step as OK."""
        now = self._clock()
        with self._lock:
            step = self._steps.get(step_id)
            if step is None or step.status is not StepStatus.RUNNING:
                return
            step.finished_at = now
            step.status = StepStatus.OK
            if detail is not None:
                step.detail = detail
            if evidence_ids is not None:
                step.evidence_ids = list(evidence_ids)
        self._notify()

    def fail(
        self,
        step_id: str,
        cause: str,
        *,
        evidence_ids: Optional[list[str]] = None,
    ) -> None:
        """Mark a step as FAILED with a typed cause."""
        now = self._clock()
        with self._lock:
            step = self._steps.get(step_id)
            if step is None or step.status is not StepStatus.RUNNING:
                return
            step.finished_at = now
            step.status = StepStatus.FAILED
            step.detail = cause
            if evidence_ids is not None:
                step.evidence_ids = list(evidence_ids)
        self._notify()

    # ---- snapshot ----

    def snapshot(self) -> ProgressSnapshot:
        with self._lock:
            steps = sorted(self._steps.values(), key=lambda s: s.id)
            completed = sum(1 for s in steps if s.status is StepStatus.OK)
            failed = sum(1 for s in steps if s.status is StepStatus.FAILED)
            running = next((s.id for s in steps if s.status is StepStatus.RUNNING), None)
            elapsed = 0.0
            if self._started_at is not None:
                elapsed = max(0.0, self._clock() - self._started_at)
            return ProgressSnapshot(
                run_id=self._run_id,
                total_steps=len(steps),
                completed_steps=completed,
                failed_steps=failed,
                running_step=running,
                elapsed_s=elapsed,
                steps=list(steps),
                cancelled=self._cancelled,
            )

    def render_text(self) -> str:
        """Render a one-shot textual summary (suitable for CLI / logs)."""
        snap = self.snapshot()
        lines = [
            f"Run {snap.run_id}  "
            f"({snap.completed_steps}/{snap.total_steps} ok, {snap.failed_steps} failed, "
            f"elapsed {snap.elapsed_s:.1f}s)"
            + ("  CANCELLED" if snap.cancelled else "")
        ]
        for s in snap.steps:
            dur = f" ({s.duration_s:.2f}s)" if s.duration_s is not None else ""
            detail = f"  {s.detail}" if s.detail else ""
            evid = f"  ev={','.join(s.evidence_ids)}" if s.evidence_ids else ""
            lines.append(f"  [{s.status.value:<10}] {s.name}{dur}{detail}{evid}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """A JSON-serializable snapshot of the reporter (for API responses)."""
        snap = self.snapshot()
        return {
            "run_id": snap.run_id,
            "total_steps": snap.total_steps,
            "completed_steps": snap.completed_steps,
            "failed_steps": snap.failed_steps,
            "running_step": snap.running_step,
            "elapsed_s": snap.elapsed_s,
            "cancelled": snap.cancelled,
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "status": s.status.value,
                    "duration_s": s.duration_s,
                    "detail": s.detail,
                    "evidence_ids": s.evidence_ids,
                    "counters": s.counters,
                }
                for s in snap.steps
            ],
        }
