"""Tests for the live progress reporter."""

from __future__ import annotations

import pytest

from netops_autopilot.cli.progress import (
    ProgressReporter,
    StepStatus,
    ProgressSnapshot,
)


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
    def __call__(self) -> float:
        return self.t
    def advance(self, dt: float) -> None:
        self.t += dt


def test_empty_reporter_snapshot():
    r = ProgressReporter(run_id="r1")
    snap = r.snapshot()
    assert snap.run_id == "r1"
    assert snap.total_steps == 0
    assert snap.completed_steps == 0
    assert snap.failed_steps == 0
    assert snap.running_step is None
    assert snap.cancelled is False
    assert snap.elapsed_s == 0.0


def test_begin_returns_step_id():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    assert sid == "r1:BOND:Bind"
    snap = r.snapshot()
    assert snap.running_step == sid
    assert snap.total_steps == 1


def test_end_marks_step_ok():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.end(sid, detail="ok", evidence_ids=["e1"])
    snap = r.snapshot()
    assert snap.completed_steps == 1
    assert snap.running_step is None


def test_fail_marks_step_failed():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.fail(sid, "OPERATOR_REFUSED")
    snap = r.snapshot()
    assert snap.failed_steps == 1
    step = snap.steps[0]
    assert step.status is StepStatus.FAILED
    assert step.detail == "OPERATOR_REFUSED"


def test_update_only_changes_metadata():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.update(sid, detail="waiting on operator", counters={"q": 1})
    r.update(sid, evidence_ids=["e1", "e2"])
    snap = r.snapshot()
    step = snap.steps[0]
    assert step.detail == "waiting on operator"
    assert step.evidence_ids == ["e1", "e2"]
    assert step.counters == {"q": 1}
    assert step.status is StepStatus.RUNNING


def test_update_after_end_is_noop():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.end(sid)
    r.update(sid, detail="should be ignored")
    snap = r.snapshot()
    assert snap.steps[0].detail == ""


def test_duration_uses_injected_clock():
    clock = _FakeClock()
    r = ProgressReporter(run_id="r1", clock=clock)
    sid = r.begin("BOND", "Bind")
    clock.advance(2.5)
    r.end(sid)
    snap = r.snapshot()
    assert snap.steps[0].duration_s == 2.5
    assert snap.elapsed_s == 2.5


def test_cancellation_is_idempotent():
    r = ProgressReporter(run_id="r1")
    r.cancel()
    r.cancel()
    r.cancel()
    assert r.cancelled is True
    assert r.snapshot().cancelled is True


def test_cancellation_does_not_complete_running_step():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.cancel()
    snap = r.snapshot()
    # The step stays RUNNING; cancel is a request, not a hard kill.
    assert snap.steps[0].status is StepStatus.RUNNING
    assert snap.cancelled is True


def test_subscribe_receives_updates():
    r = ProgressReporter(run_id="r1")
    received: list[ProgressSnapshot] = []
    listener = lambda s: received.append(s)  # noqa: E731
    r.subscribe(listener)
    sid = r.begin("BOND", "Bind")
    r.end(sid)
    assert len(received) >= 2  # begin + end
    assert all(isinstance(s, ProgressSnapshot) for s in received)


def test_listener_exceptions_do_not_break_reporter():
    r = ProgressReporter(run_id="r1")
    def bad(_):
        raise RuntimeError("boom")
    r.subscribe(bad)
    sid = r.begin("BOND", "Bind")
    r.end(sid)  # must not raise


def test_unsubscribe_stops_callbacks():
    r = ProgressReporter(run_id="r1")
    received: list[int] = []
    def listener(_):
        received.append(1)
    r.subscribe(listener)
    r.begin("BOND", "Bind")
    r.unsubscribe(listener)
    r.end(r.snapshot().steps[0].id)
    assert len(received) == 1


def test_render_text_includes_all_steps():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.end(sid, detail="ok", evidence_ids=["e1"])
    out = r.render_text()
    assert "Run r1" in out
    assert "1/1 ok" in out
    assert "Bind" in out
    assert "ok" in out
    assert "e1" in out


def test_to_dict_is_json_friendly():
    import json
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind")
    r.end(sid)
    d = r.to_dict()
    # Must be JSON-serializable.
    json.dumps(d)
    assert d["run_id"] == "r1"
    assert d["completed_steps"] == 1


def test_thread_safety():
    """Many threads starting and ending steps must not corrupt state."""
    import threading
    r = ProgressReporter(run_id="r1")
    def worker(n):
        for i in range(50):
            sid = r.begin("PHASE", f"step-{n}-{i}")
            r.end(sid)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    snap = r.snapshot()
    assert snap.total_steps == 8 * 50
    assert snap.completed_steps == 8 * 50
    assert snap.failed_steps == 0


def test_step_id_can_be_explicit():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind", step_id="custom-id")
    assert sid == "custom-id"


def test_begin_twice_for_same_id_resets_step():
    r = ProgressReporter(run_id="r1")
    sid = r.begin("BOND", "Bind", step_id="x")
    r.end(sid)
    sid2 = r.begin("BOND", "Bind", step_id="x")
    # The second begin replaces the step (re-run).
    snap = r.snapshot()
    assert snap.total_steps == 1
    assert snap.steps[0].status is StepStatus.RUNNING
