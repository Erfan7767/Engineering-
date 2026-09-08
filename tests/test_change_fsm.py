"""FSM-2 Change Lifecycle: full spine, branch guards, human-only gates."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.fsm import change_fsm as cf
from netops_autopilot.fsm.evidence import ctx, ev
from netops_autopilot.ledger.models import OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore

ENGINE = OperatorIdentity(kind="ENGINE", id="E15")
SCOPE = cf.SCOPE


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    return store, counters, cf.build_change_fsm(recorder=store, counters=counters)


def test_state_set_matches_spec_exactly():
    assert cf.ALL_STATES == frozenset({
        "DRAFT", "VALIDATED", "PLANNED", "RISK_ASSESSED", "AUTHORIZED",
        "ARMED", "APPLYING", "APPLIED", "VERIFYING", "VERIFIED", "CLEANED",
        "CLOSED", "REJECTED", "PARTIAL", "FAILED", "ROLLED_BACK",
        "RECOVERING", "MANUAL_REQUIRED",
    })


def test_full_happy_path_spine(rig):
    store, counters, fsm = rig
    steps = [
        (cf.VALIDATED, ctx(ev(SCOPE, "validation_fabric:PASS", "e1"))),
        (cf.PLANNED, ctx(ev(SCOPE, "dag:total_order", "e2"), ev(SCOPE, "dag:permanent_constraints_ok", "e3"))),
        (cf.RISK_ASSESSED, ctx(ev(SCOPE, "blast_radius:recorded", "e4"), ev(SCOPE, "risk_class:recorded", "e5"))),
        (cf.AUTHORIZED, ctx(
            ev(SCOPE, "readiness:all_true", "e6"),
            ev(SCOPE, "gate_verdict:ALLOW", "e7"),
        ), {"gate_class": "LOW_RISK"}),
        (cf.ARMED, ctx(
            ev(SCOPE, "window:valid", "e8"), ev(SCOPE, "scheduler:no_conflict", "e9"),
            ev(SCOPE, "lock:acquirable", "e10"), ev(SCOPE, "rollback:READY", "e11"),
            ev(SCOPE, "scope_lock:recorded", "e12"),
        )),
        (cf.APPLYING, ctx(ev(SCOPE, "authorized_state:reverified", "e13"), ev(SCOPE, "allowlist:rechecked", "e14"))),
        (cf.APPLIED, ctx(ev(SCOPE, "apply:all_stages_ack", "e15"))),
        (cf.VERIFYING, ctx(ev(SCOPE, "apply:settled", "e16"))),
        (cf.VERIFIED, ctx(ev(SCOPE, "tests:all_pass", "e17"))),
        (cf.CLEANED, ctx(ev(SCOPE, "temp_resources:zero", "e18"))),
        (cf.CLOSED, ctx(ev(SCOPE, "twin:refreshed_from_observed", "e19"),
                        ev(SCOPE, "docs:emitted", "e20"), ev(SCOPE, "audit:chain_complete", "e21"))),
    ]
    for step in steps:
        target, c = step[0], step[1]
        extra = step[2] if len(step) > 2 else {}
        r = fsm.fire("chg-1", target, {**c, **extra}, ENGINE)
        assert r.success, f"step ->{target} failed: {r.failure}"
    assert fsm.state == cf.CLOSED
    trs = store.transitions()
    assert [t.guard_id for t in trs] == [f"2.{n}" for n in (1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13)]


def test_not_modeled_must_be_recorded_before_validated(rig):
    _, _, fsm = rig
    c = ctx(ev(SCOPE, "validation_fabric:PASS", "e1"), ev(SCOPE, "validation_fabric:NOT_MODELED", "e2"))
    r = fsm.fire("chg-1", cf.VALIDATED, c, ENGINE)
    assert not r.success and "NOT_MODELED" in r.failure.causes[0]
    c2 = ctx(ev(SCOPE, "validation_fabric:PASS", "e1"),
             ev(SCOPE, "validation_fabric:NOT_MODELED", "e2"),
             ev(SCOPE, "validation_fabric:not_modeled_recorded", "e3"))
    assert fsm.fire("chg-1", cf.VALIDATED, c2, ENGINE).success


def test_arm_requires_rollback_ready_adr0009(rig):
    _, _, fsm = rig
    fsm.state = cf.AUTHORIZED
    without = ctx(
        ev(SCOPE, "window:valid"), ev(SCOPE, "scheduler:no_conflict"),
        ev(SCOPE, "lock:acquirable"), ev(SCOPE, "scope_lock:recorded"),
    )
    r = fsm.fire("chg-1", cf.ARMED, without, ENGINE)
    assert not r.success and "rollback:READY" in r.failure.causes[0]


def test_irreversible_gate_requires_human_decision_every_mode(rig):
    """L06/ADR-0007 realized in guard 2.4: engine verdict alone is not enough."""
    _, _, fsm = rig
    fsm.state = cf.RISK_ASSESSED
    engine_only = ctx(
        ev(SCOPE, "readiness:all_true"), ev(SCOPE, "gate_verdict:ALLOW"),
        ev(SCOPE, "approval:rbac_identity"), ev(SCOPE, "approval:mfa_verified"),
    )
    r = fsm.fire("chg-1", cf.AUTHORIZED, {**engine_only, "gate_class": "IRREVERSIBLE"}, ENGINE)
    assert not r.success and "gate_verdict:HUMAN_DECIDED" in r.failure.causes[0]
    with_human = ctx(*engine_only["evidence"], ev(SCOPE, "gate_verdict:HUMAN_DECIDED"))
    assert fsm.fire("chg-1", cf.AUTHORIZED, {**with_human, "gate_class": "IRREVERSIBLE"}, ENGINE).success


def test_high_risk_gate_requires_mfa_identity(rig):
    _, _, fsm = rig
    fsm.state = cf.RISK_ASSESSED
    no_mfa = ctx(ev(SCOPE, "readiness:all_true"), ev(SCOPE, "gate_verdict:ALLOW"))
    r = fsm.fire("chg-1", cf.AUTHORIZED, {**no_mfa, "gate_class": "HIGH_RISK"}, ENGINE)
    assert not r.success and "approval:mfa_verified" in r.failure.causes[0]


def test_gate_class_absent_is_denied(rig):
    _, _, fsm = rig
    fsm.state = cf.RISK_ASSESSED
    r = fsm.fire("chg-1", cf.AUTHORIZED, ctx(ev(SCOPE, "readiness:all_true"), ev(SCOPE, "gate_verdict:ALLOW")), ENGINE)
    assert not r.success and "gate_class absent" in r.failure.causes[0]


def test_apply_failure_branch_requires_t4_report(rig):
    _, _, fsm = rig
    fsm.state = cf.APPLYING
    r = fsm.fire("chg-1", cf.FAILED, ctx(ev(SCOPE, "failure_orchestrator:decision")), ENGINE)
    assert not r.success and "counts_and_causes" in r.failure.causes[0]
    ok = ctx(ev(SCOPE, "failure_orchestrator:decision"), ev(SCOPE, "failure_report:counts_and_causes"))
    assert fsm.fire("chg-1", cf.FAILED, ok, ENGINE).success
    # T4 escalation path to MANUAL_REQUIRED needs emitted instructions.
    assert not fsm.fire("chg-1", cf.MANUAL_REQUIRED, ctx(), ENGINE).success
    assert fsm.fire("chg-1", cf.MANUAL_REQUIRED, ctx(ev(SCOPE, "human_task:instructions_emitted")), ENGINE).success


def test_verify_fail_rollback_paths(rig):
    _, _, fsm = rig
    fsm.state = cf.VERIFYING
    r = fsm.fire("chg-1", cf.ROLLED_BACK, ctx(ev(SCOPE, "rollback:TRIGGERED")), ENGINE)
    assert not r.success and "rollback:SUCCEEDED" in r.failure.causes[0]
    fsm2_state = ctx(ev(SCOPE, "rollback:TRIGGERED"), ev(SCOPE, "rollback:SUCCEEDED"))
    assert fsm.fire("chg-1", cf.ROLLED_BACK, fsm2_state, ENGINE).success


def test_verify_recovering_on_failed_rollback(rig):
    _, _, fsm = rig
    fsm.state = cf.VERIFYING
    r = fsm.fire("chg-1", cf.RECOVERING, ctx(ev(SCOPE, "rollback:TRIGGERED"), ev(SCOPE, "rollback:FAILED")), ENGINE)
    assert r.success


def test_rejection_available_pre_apply_only(rig):
    _, counters, fsm = rig
    reject_ctx = ctx(ev(SCOPE, "verdict:REJECTED"), ev(SCOPE, "verdict:reason_recorded"))
    assert fsm.fire("chg-1", cf.REJECTED, reject_ctx, ENGINE).success
    assert counters.value("gate_bypass") == 0
    fsm2 = cf.build_change_fsm(recorder=fsm._recorder, counters=counters)
    fsm2.state = cf.APPLYING
    r = fsm2.fire("chg-1", cf.REJECTED, reject_ctx, ENGINE)
    assert r.illegal and counters.value("gate_bypass") == 1


def test_non_pass_tests_need_documented_human_acceptance(rig):
    _, _, fsm = rig
    fsm.state = cf.VERIFYING
    r = fsm.fire("chg-1", cf.VERIFIED, ctx(ev(SCOPE, "tests:non_pass_present")), ENGINE)
    assert not r.success
    ok = ctx(ev(SCOPE, "tests:non_pass_present"), ev(SCOPE, "tests:human_acceptance_per_non_pass"))
    assert fsm.fire("chg-1", cf.VERIFIED, ok, ENGINE).success
