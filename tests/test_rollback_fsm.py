"""FSM-3 Rollback: the READY conjunction, trigger/verify paths, typed dead-ends."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.fsm import rollback_fsm as rf
from netops_autopilot.fsm.evidence import ctx, ev
from netops_autopilot.ledger.models import OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore

ENGINE = OperatorIdentity(kind="ENGINE", id="E16")
SCOPE = rf.SCOPE


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    return store, counters, rf.build_rollback_fsm(recorder=store, counters=counters)


def test_state_set_matches_spec():
    assert rf.ALL_STATES == frozenset({
        "INIT", "NOT_SUPPORTED", "NOT_CONFIGURED", "NOT_READY", "READY",
        "ARMED", "CONFIRMED", "ROLLBACK_TRIGGERED", "ROLLBACK_SUCCEEDED",
        "ROLLBACK_FAILED", "UNKNOWN",
    })


def test_ready_requires_all_seven_preconditions(rig):
    _, _, fsm = rig
    fsm.fire("rb-1", rf.NOT_CONFIGURED, ctx(ev(SCOPE, "matrix:mechanism_supported", "m1")), ENGINE)
    fsm.fire("rb-1", rf.NOT_READY, ctx(ev(SCOPE, "artifact:exists", "a1")), ENGINE)
    # Six of seven ⇒ deny, naming the missing one exactly.
    partial = ctx(*[ev(SCOPE, k, f"p{i}") for i, k in enumerate(rf.READY_PRECONDITIONS[:6])])
    r = fsm.fire("rb-1", rf.READY, partial, ENGINE)
    assert not r.success
    assert rf.READY_PRECONDITIONS[6] in r.failure.causes[0]
    full = ctx(*[ev(SCOPE, k, f"p{i}") for i, k in enumerate(rf.READY_PRECONDITIONS)])
    assert fsm.fire("rb-1", rf.READY, full, ENGINE).success
    assert fsm.state == rf.READY


def test_mechanism_absent_is_terminal_not_supported(rig):
    _, _, fsm = rig
    assert fsm.fire("rb-1", rf.NOT_SUPPORTED, ctx(ev(SCOPE, "matrix:mechanism_absent")), ENGINE).success
    r = fsm.fire("rb-1", rf.NOT_CONFIGURED, ctx(ev(SCOPE, "matrix:mechanism_supported")), ENGINE)
    assert r.illegal  # NOT_SUPPORTED is terminal (T6 honesty)


def test_arm_requires_fsm2_binding(rig):
    _, _, fsm = rig
    fsm.state = rf.READY
    r = fsm.fire("rb-1", rf.ARMED, ctx(), ENGINE)
    assert not r.success and "fsm2:ARMED_bound" in r.failure.causes[0]
    assert fsm.fire("rb-1", rf.ARMED, ctx(ev(SCOPE, "fsm2:ARMED_bound")), ENGINE).success


def test_trigger_then_success_requires_post_verify(rig):
    """ADR-0009 §5: rollback without verification is not success."""
    _, _, fsm = rig
    fsm.state = rf.ARMED
    fsm.fire("rb-1", rf.ROLLBACK_TRIGGERED, ctx(ev(SCOPE, "rollback:trigger_reason", "t1")), ENGINE)
    r = fsm.fire("rb-1", rf.ROLLBACK_SUCCEEDED, ctx(ev(SCOPE, "rollback:reapplied")), ENGINE)
    assert not r.success and "rollback:post_verify_pass" in r.failure.causes[0]
    ok = ctx(ev(SCOPE, "rollback:reapplied"), ev(SCOPE, "rollback:post_verify_pass"), ev(SCOPE, "mgmt_path:reachable"))
    assert fsm.fire("rb-1", rf.ROLLBACK_SUCCEEDED, ok, ENGINE).success


def test_trigger_then_failed_path(rig):
    _, _, fsm = rig
    fsm.state = rf.ROLLBACK_TRIGGERED
    r = fsm.fire("rb-1", rf.ROLLBACK_FAILED, ctx(ev(SCOPE, "rollback:succeed_conjunct_failed")), ENGINE)
    assert r.success


def test_unknown_on_vanished_evidence(rig):
    _, _, fsm = rig
    fsm.state = rf.ARMED
    assert fsm.fire("rb-1", rf.UNKNOWN, ctx(ev(SCOPE, "evidence:vanished")), ENGINE).success


def test_confirmed_requires_apply_ok_and_window(rig):
    _, _, fsm = rig
    fsm.state = rf.ARMED
    r = fsm.fire("rb-1", rf.CONFIRMED, ctx(ev(SCOPE, "apply:ok")), ENGINE)
    assert not r.success and "verification_window:opened" in r.failure.causes[0]
    ok = ctx(ev(SCOPE, "apply:ok"), ev(SCOPE, "verification_window:opened"))
    assert fsm.fire("rb-1", rf.CONFIRMED, ok, ENGINE).success


def test_ready_preconditions_match_schema_enum():
    """Guard evidence kinds must stay 1:1 with rollback.schema.json."""
    import json
    from pathlib import Path

    schema = json.loads((Path(__file__).resolve().parents[1] / "specs" / "schemas" / "rollback.schema.json").read_text())
    enum = set(schema["properties"]["preconditions"]["items"]["properties"]["name"]["enum"])
    guard_kinds = {k.split(":", 1)[1] for k in rf.READY_PRECONDITIONS}
    assert guard_kinds == enum
