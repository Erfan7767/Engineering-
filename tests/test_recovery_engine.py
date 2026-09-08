"""E17 Recovery Engine: FSM-5 ladder, matrix skips, L5 human gate, loss."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.recovery_engine import DESTRUCTIVE_LEVELS, RecoveryEngine
from netops_autopilot.fsm import recovery_fsm as rc
from netops_autopilot.ledger.store import LedgerStore

PLATFORM = "mikrotik/routeros"


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    fsm = rc.build_recovery_fsm(recorder=store, counters=counters)
    engine = RecoveryEngine(fsm, CapabilityEngine.load_builtin(), PLATFORM)
    return fsm, engine


def started(engine):
    engine.start("dev-1", "failure-ev-1", "chg-1")


# --------------------------------------------------------------------- start
def test_start_requires_classification_and_binding(rig):
    fsm, engine = rig
    with pytest.raises(Failure) as exc:
        engine.start("dev-1", "", "chg-1")
    assert "RECOVERY_BINDING_INCOMPLETE" in exc.value.causes[0]
    started(engine)
    assert fsm.state == rc.ESCALATING_L0


def test_escalation_before_start_refused(rig):
    _, engine = rig
    with pytest.raises(Failure) as exc:
        engine.escalate("dev-1", 0, attempt_failed=True)
    assert "RECOVERY_NOT_STARTED" in exc.value.causes[0]


# ------------------------------------------------------------ attempt honesty
def test_supported_level_requires_attempt_outcome(rig):
    _, engine = rig
    started(engine)
    with pytest.raises(Failure) as exc:
        engine.escalate("dev-1", 0)  # no attempt result supplied
    assert "ATTEMPT_RESULT_REQUIRED" in exc.value.causes[0]
    with pytest.raises(Failure) as exc:
        engine.escalate("dev-1", 0, attempt_failed=False)
    assert "ATTEMPT_NOT_FAILED" in exc.value.causes[0]


def test_escalation_ladder_with_failed_attempts(rig):
    fsm, engine = rig
    started(engine)
    engine.escalate("dev-1", 0, attempt_failed=True)
    assert fsm.state == rc.ESCALATING_L1
    engine.escalate("dev-1", 1, attempt_failed=True)
    assert fsm.state == rc.ESCALATING_L2


def test_oob_skip_is_recorded_not_assumed(rig):
    """ADR-0004: matrix says oob=UNKNOWN ⇒ L3 recorded as NOT_CONFIGURED,
    escalation proceeds WITHOUT an attempt (v1 default, documented)."""
    fsm, engine = rig
    started(engine)
    engine.escalate("dev-1", 0, attempt_failed=True)
    engine.escalate("dev-1", 1, attempt_failed=True)
    engine.escalate("dev-1", 2, attempt_failed=True)
    assert fsm.state == rc.ESCALATING_L3
    engine.escalate("dev-1", 3)  # no attempt needed — matrix excuse recorded
    assert fsm.state == rc.ESCALATING_L4


# ------------------------------------------------------------------ L5 gate
def test_entering_destructive_tier_needs_human_decision(rig):
    fsm, engine = rig
    started(engine)
    for level in (0, 1, 2, 3):
        engine.escalate("dev-1", level, attempt_failed=True if level != 3 else None)
    assert fsm.state == rc.ESCALATING_L4
    with pytest.raises(Failure) as exc:
        engine.escalate("dev-1", 4, attempt_failed=True)
    assert "DESTRUCTIVE_GATE_REQUIRED" in exc.value.causes[0]
    with pytest.raises(Failure):
        engine.escalate_into_destructive("dev-1", "")
    engine.escalate_into_destructive("dev-1", "human-decision-ev-77")
    assert fsm.state == rc.ESCALATING_L5
    assert 5 in DESTRUCTIVE_LEVELS and 6 in DESTRUCTIVE_LEVELS and 7 in DESTRUCTIVE_LEVELS


# ------------------------------------------------------------------ outcomes
def test_recovery_requires_all_three_conjuncts(rig):
    fsm, engine = rig
    started(engine)
    engine.recovered("dev-1", "reach-1", "identity-1", "reclass-1")
    assert fsm.state == rc.RECOVERED


def test_physical_tiers_wait_for_human(rig):
    fsm, engine = rig
    started(engine)
    for level in (0, 1, 2, 3):
        engine.escalate("dev-1", level, attempt_failed=True if level != 3 else None)
    engine.escalate_into_destructive("dev-1", "human-ev")
    engine.escalate("dev-1", 5, attempt_failed=True)
    assert fsm.state == rc.ESCALATING_L6
    with pytest.raises(Failure):
        engine.human_required("dev-1", "")
    engine.human_required("dev-1", "instructions-ev")
    assert fsm.state == rc.HUMAN_REQUIRED


def test_exhausted_paths_end_in_lost(rig):
    fsm, engine = rig
    started(engine)
    with pytest.raises(Failure):
        engine.lost("dev-1", "")
    engine.lost("dev-1", "exhausted-ev")
    assert fsm.state == rc.LOST


def test_level_range_is_typed(rig):
    _, engine = rig
    started(engine)
    with pytest.raises(Failure) as exc:
        engine.escalate("dev-1", 7, attempt_failed=True)
    assert "RECOVERY_LEVEL_OUT_OF_RANGE" in exc.value.causes[0]
