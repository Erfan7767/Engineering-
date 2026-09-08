"""E14 Autonomy Authority: ceiling lock, gate verdicts, readiness algebra."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.autonomy import (
    Approval,
    AutonomyAuthority,
    AutonomyLevel,
    DecisionReadiness,
    Verdict,
)


@pytest.fixture()
def m3():
    return AutonomyAuthority()  # default ceiling = locked M3


# ------------------------------------------------------------------ ceiling
def test_default_ceiling_is_locked_m3(m3):
    assert m3.ceiling is AutonomyLevel.M3_CONTROLLED


def test_ceiling_above_m3_refuses_construction():
    with pytest.raises(Failure) as exc:
        AutonomyAuthority(ceiling=AutonomyLevel.M4_HIGH)
    assert "AUTONOMY_CEILING_LOCKED" in exc.value.causes[0]
    with pytest.raises(Failure):
        AutonomyAuthority(ceiling=AutonomyLevel.M5_FULL)


def test_approval_without_identity_is_typed():
    with pytest.raises(Failure) as exc:
        Approval(rbac_identity="", mfa_verified=True)
    assert "APPROVAL_IDENTITY_EMPTY" in exc.value.causes[0]


# ------------------------------------------------------------ gate verdicts
def test_low_risk_auto_executes_at_m3(m3):
    d = m3.decide(gate_class="LOW_RISK", risk_class="LOW_RISK", preflight_not_modeled=False)
    assert d.verdict is Verdict.AUTO_EXECUTE
    assert d.approval_satisfied is True
    assert d.human_decided is False


def test_high_risk_requires_mfa_approval(m3):
    d = m3.decide(gate_class="HIGH_RISK", risk_class="HIGH_RISK", preflight_not_modeled=False)
    assert d.verdict is Verdict.APPROVAL_REQUIRED
    assert d.approval_satisfied is False
    ok = m3.decide(gate_class="HIGH_RISK", risk_class="HIGH_RISK",
                   preflight_not_modeled=False,
                   approval=Approval("netops-admin@corp", mfa_verified=True))
    assert ok.verdict is Verdict.APPROVAL_REQUIRED and ok.approval_satisfied is True
    no_mfa = m3.decide(gate_class="HIGH_RISK", risk_class="HIGH_RISK",
                       preflight_not_modeled=False,
                       approval=Approval("netops-admin@corp", mfa_verified=False))
    assert no_mfa.approval_satisfied is False


@pytest.mark.parametrize("gate", ["IRREVERSIBLE", "DESTRUCTIVE"])
def test_human_only_gates_in_every_mode(m3, gate):
    d = m3.decide(gate_class=gate, risk_class=gate, preflight_not_modeled=False)
    assert d.verdict is Verdict.HUMAN_ONLY
    assert d.human_decided is False
    decided = m3.decide(gate_class=gate, risk_class=gate, preflight_not_modeled=False,
                        approval=Approval("chief-eng@corp", mfa_verified=True))
    assert decided.verdict is Verdict.HUMAN_ONLY
    assert decided.human_decided is True
    # even a lower ceiling cannot relax human-only gates
    low = AutonomyAuthority(ceiling=AutonomyLevel.M1_ASSISTED)
    assert low.decide(gate_class=gate, risk_class=gate,
                      preflight_not_modeled=False).verdict is Verdict.HUMAN_ONLY


def test_not_modeled_is_terminal_even_with_approval(m3):
    d = m3.decide(gate_class="LOW_RISK", risk_class="LOW_RISK",
                  preflight_not_modeled=True,
                  approval=Approval("admin@corp", mfa_verified=True))
    assert d.verdict is Verdict.BLOCKED
    assert any("NOT_MODELED_TERMINAL" in r for r in d.reasons)


def test_unknown_gate_or_risk_is_blocked_never_defaulted(m3):
    assert m3.decide(gate_class="MEDIUM?", risk_class="LOW_RISK",
                     preflight_not_modeled=False).verdict is Verdict.BLOCKED
    assert m3.decide(gate_class="LOW_RISK", risk_class="",
                     preflight_not_modeled=False).verdict is Verdict.BLOCKED


def test_lower_ceiling_never_auto_executes():
    for level in (AutonomyLevel.M0_MANUAL, AutonomyLevel.M1_ASSISTED, AutonomyLevel.M2_SUPERVISED):
        d = AutonomyAuthority(ceiling=level).decide(
            gate_class="LOW_RISK", risk_class="LOW_RISK", preflight_not_modeled=False)
        assert d.verdict is Verdict.APPROVAL_REQUIRED
        assert any("CEILING_BELOW_M3" in r for r in d.reasons)


def test_decision_is_deterministic(m3):
    a = m3.decide(gate_class="HIGH_RISK", risk_class="HIGH_RISK", preflight_not_modeled=False)
    b = m3.decide(gate_class="HIGH_RISK", risk_class="HIGH_RISK", preflight_not_modeled=False)
    assert a == b


# ---------------------------------------------------------------- readiness
def test_readiness_all_true_requires_every_conjunct():
    r = DecisionReadiness(intent_compiled=True, fabric_pass=True, dag_built=True,
                          blast_recorded=True, rollback_ready=True, twin_fresh=True,
                          capability_confirmed=True, no_conflicting_change=True)
    assert r.all_true is True
    assert r.false_conjuncts() == ()


def test_readiness_unknown_counts_as_false():
    r = DecisionReadiness(intent_compiled=True, fabric_pass=True, dag_built=True,
                          blast_recorded=True, rollback_ready=None, twin_fresh=True,
                          capability_confirmed=True, no_conflicting_change=True)
    assert r.all_true is False
    assert r.unknown_conjuncts() == ("rollback_ready",)
    assert r.false_conjuncts() == ("rollback_ready",)


def test_readiness_defaults_are_unknown():
    r = DecisionReadiness()
    assert r.all_true is False
    assert len(r.unknown_conjuncts()) == 8
