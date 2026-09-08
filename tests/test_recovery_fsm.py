"""FSM-5 Recovery Hierarchy: escalation ladder, L5 human gate, loss semantics."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.fsm import recovery_fsm as rc
from netops_autopilot.fsm.evidence import ctx, ev
from netops_autopilot.ledger.models import OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore

ENGINE = OperatorIdentity(kind="ENGINE", id="E17")
SC = rc.SCOPE


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    return store, counters, rc.build_recovery_fsm(recorder=store, counters=counters)


def enter_l0(fsm):
    return fsm.fire("dev-1", rc.ESCALATING_L0,
                    ctx(ev(SC, "failure:classified_recoverable"), ev(SC, "change:bound")), ENGINE)


def test_state_set_matches_spec():
    assert rc.ALL_STATES == frozenset({
        "NOT_NEEDED", "ESCALATING_L0", "ESCALATING_L1", "ESCALATING_L2",
        "ESCALATING_L3", "ESCALATING_L4", "ESCALATING_L5", "ESCALATING_L6",
        "ESCALATING_L7", "RECOVERED", "HUMAN_REQUIRED", "LOST",
    })


def test_entry_requires_classification_and_change_binding(rig):
    _, _, fsm = rig
    r = fsm.fire("dev-1", rc.ESCALATING_L0, ctx(ev(SC, "failure:classified_recoverable")), ENGINE)
    assert not r.success and "change:bound" in r.failure.causes[0]
    assert enter_l0(fsm).success


def test_escalation_on_attempt_failure(rig):
    _, _, fsm = rig
    enter_l0(fsm)
    assert fsm.fire("dev-1", rc.ESCALATING_L1, ctx(ev(SC, "attempt:L0_failed")), ENGINE).success
    assert fsm.fire("dev-1", rc.ESCALATING_L2, ctx(ev(SC, "attempt:L1_failed")), ENGINE).success


def test_oob_skip_recorded_not_assumed(rig):
    """ADR-0004: L3 absent ⇒ skip via matrix evidence, recorded (not hardcoded)."""
    _, _, fsm = rig
    enter_l0(fsm)
    fsm.state = rc.ESCALATING_L2
    r = fsm.fire("dev-1", rc.ESCALATING_L3, ctx(), ENGINE)
    assert not r.success  # cannot enter without evidence of either kind
    assert fsm.fire("dev-1", rc.ESCALATING_L3, ctx(ev(SC, "matrix:L2_not_configured")), ENGINE).success


def test_entering_l5_requires_destructive_human_gate(rig):
    """5.4/L06: bootloader tier is human-decided in every mode."""
    _, _, fsm = rig
    fsm.state = rc.ESCALATING_L4
    r = fsm.fire("dev-1", rc.ESCALATING_L5, ctx(ev(SC, "attempt:L4_failed")), ENGINE)
    assert not r.success and "gate:DESTRUCTIVE_human_decision" in r.failure.causes[0]
    ok = ctx(ev(SC, "attempt:L4_failed"), ev(SC, "gate:DESTRUCTIVE_human_decision", "human-9"))
    assert fsm.fire("dev-1", rc.ESCALATING_L5, ok, ENGINE).success


def test_recovered_requires_full_triple(rig):
    _, _, fsm = rig
    fsm.state = rc.ESCALATING_L1
    r = fsm.fire("dev-1", rc.RECOVERED, ctx(ev(SC, "device:reachable_again")), ENGINE)
    assert not r.success and "identity:reconfirmed" in r.failure.causes[0]
    ok = ctx(ev(SC, "device:reachable_again"), ev(SC, "identity:reconfirmed"), ev(SC, "state:reclassified"))
    assert fsm.fire("dev-1", rc.RECOVERED, ok, ENGINE).success


def test_human_required_waits_for_evidence_then_recovers(rig):
    _, _, fsm = rig
    fsm.state = rc.ESCALATING_L6
    assert fsm.fire("dev-1", rc.HUMAN_REQUIRED, ctx(ev(SC, "human_task:instructions_emitted")), ENGINE).success
    r = fsm.fire("dev-1", rc.RECOVERED, ctx(ev(SC, "device:reachable_again")), ENGINE)
    assert not r.success  # still needs identity + reclassification
    ok = ctx(ev(SC, "device:reachable_again"), ev(SC, "identity:reconfirmed"), ev(SC, "state:reclassified"))
    assert fsm.fire("dev-1", rc.RECOVERED, ok, ENGINE).success


def test_lost_from_any_level_and_terminal(rig):
    _, counters, fsm = rig
    for level in rc._LEVELS:
        fsm.state = level
        assert fsm.fire("dev-1", rc.LOST, ctx(ev(SC, "paths:all_exhausted")), ENGINE).success, level
    fsm.state = rc.LOST
    r = fsm.fire("dev-1", rc.RECOVERED, ctx(), ENGINE)
    assert r.illegal and counters.value("gate_bypass") == 1


def test_full_ladder_walk_with_recorded_transitions(rig):
    store, _, fsm = rig
    enter_l0(fsm)
    steps = [
        (rc.ESCALATING_L1, "attempt:L0_failed"),
        (rc.ESCALATING_L2, "matrix:L1_not_supported"),
        (rc.ESCALATING_L3, "attempt:L2_failed"),
        (rc.ESCALATING_L4, "matrix:L3_not_configured"),
        (rc.ESCALATING_L5, "attempt:L4_failed"),  # plus gate below
    ]
    for target, kind in steps[:4]:
        assert fsm.fire("dev-1", target, ctx(ev(SC, kind)), ENGINE).success, target
    ok = ctx(ev(SC, "attempt:L4_failed"), ev(SC, "gate:DESTRUCTIVE_human_decision", "human-9"))
    assert fsm.fire("dev-1", rc.ESCALATING_L5, ok, ENGINE).success
    trs = store.transitions()
    assert [t.guard_id for t in trs] == ["5.1", "5.2", "5.2", "5.2", "5.2", "5.2"]
    assert all(t.fsm == rc.FSM_LABEL for t in trs)


def test_l5_then_physical_tiers(rig):
    _, _, fsm = rig
    fsm.state = rc.ESCALATING_L5
    assert fsm.fire("dev-1", rc.ESCALATING_L6, ctx(ev(SC, "attempt:L5_failed")), ENGINE).success
    assert fsm.fire("dev-1", rc.ESCALATING_L7, ctx(ev(SC, "matrix:L6_not_supported")), ENGINE).success
    assert fsm.fire("dev-1", rc.HUMAN_REQUIRED, ctx(ev(SC, "human_task:instructions_emitted")), ENGINE).success
