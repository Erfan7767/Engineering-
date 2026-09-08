"""E18 Failure Orchestrator: deterministic decision algebra (guard 2.8)."""

import pytest

from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.engines.config_ir import EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.failure_orchestrator import (
    Decision, FailureOrchestrator, FailureScenario,
)


def node(node_id, reversibility=Reversibility.REVERSIBLE_BY_REPLACE, destructive=False):
    params = {"destructive": True} if destructive else {}
    return IRNode(node_id=node_id, target=EntityRef("DEVICE", "dev-1"),
                  operation=Operation.CREATE, feature="vlan", vendor_os="test/os",
                  parameters=params, reversibility=reversibility)


def scenario(failure, applied=(), failed=None, remaining=(),
             attempts_used=1, attempt_budget=3, mgmt=False):
    return FailureScenario(change_id="chg-1", failure=failure, applied_nodes=tuple(applied),
                           failed_node=failed, remaining_nodes=tuple(remaining),
                           attempts_used=attempts_used, attempt_budget=attempt_budget,
                           management_path_affected=mgmt)


@pytest.fixture()
def orch():
    return FailureOrchestrator()


# ------------------------------------------------------------- halt classes
def test_manual_required_always_halts(orch):
    sc = scenario(Failure(cls=FailureClass.MANUAL_REQUIRED, causes=("PHYSICAL_INTERVENTION",)),
                  applied=(node("a"),))
    assert orch.decide(sc).decision is Decision.HALT
    assert "MANUAL_REQUIRED_CLASS" in orch.decide(sc).reasons[0]


def test_irreversible_applied_state_never_auto_rolled_back(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("STAGE_FAIL",)),
                  applied=(node("a"), node("b", reversibility=Reversibility.IRREVERSIBLE)))
    d = orch.decide(sc)
    assert d.decision is Decision.HALT
    assert "IRREVERSIBLE_APPLIED:b" in d.reasons


def test_destructive_applied_state_halts(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("STAGE_FAIL",)),
                  applied=(node("a", destructive=True),))
    assert orch.decide(sc).decision is Decision.HALT


def test_fatal_halts_even_with_replaceable_state(orch):
    sc = scenario(Failure(cls=FailureClass.FATAL, causes=("DEVICE_VANISHED",)),
                  applied=(node("a"),))
    assert orch.decide(sc).decision is Decision.HALT


# ------------------------------------------------------------------ continue
def test_retryable_within_budget_continues(orch):
    sc = scenario(Failure(cls=FailureClass.RETRYABLE, causes=("TIMEOUT",), retry_hint="backoff"),
                  applied=(node("a"),), attempts_used=1, attempt_budget=3)
    d = orch.decide(sc)
    assert d.decision is Decision.CONTINUE
    assert "RETRYABLE_BUDGET_REMAINING:1/3" in d.reasons


def test_retryable_budget_exhausted_falls_through_to_rollback(orch):
    sc = scenario(Failure(cls=FailureClass.RETRYABLE, causes=("TIMEOUT",), retry_hint="backoff"),
                  applied=(node("a"),), failed=node("a"),
                  attempts_used=3, attempt_budget=3)
    assert orch.decide(sc).decision is Decision.PARTIAL_ROLLBACK


# ------------------------------------------------------------------ isolate
def test_management_path_impact_isolates(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("MGMT_SESSION_LOST",)),
                  applied=(node("a"),), mgmt=True)
    assert orch.decide(sc).decision is Decision.ISOLATE
    assert "MANAGEMENT_PATH_IMPACT" in orch.decide(sc).reasons


# ----------------------------------------------------------- rollback paths
def test_partial_failure_class_over_replaceable_state(orch):
    failure = Failure(cls=FailureClass.PARTIAL, causes=("STAGE_ACK_MISSING",), count=2, total=5)
    sc = scenario(failure, applied=(node("a"), node("b")))
    d = orch.decide(sc)
    assert d.decision is Decision.PARTIAL_ROLLBACK
    assert (d.count_failed, d.count_total) == (2, 5)  # T4 n/N preserved


def test_tail_node_failure_is_partial_rollback(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("PARSE_ERROR",)),
                  applied=(node("a"), node("b")), failed=node("b"))
    assert orch.decide(sc).decision is Decision.PARTIAL_ROLLBACK
    assert "TAIL_NODE_FAILURE" in orch.decide(sc).reasons


def test_stage_level_failure_is_full_rollback(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("STAGE_INFRASTRUCTURE_FAIL",)),
                  applied=(node("a"), node("b")), failed=node("c"))  # failed not the tail
    assert orch.decide(sc).decision is Decision.FULL_ROLLBACK


def test_no_applied_state_never_invents_rollback(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("FIRST_STAGE_FAIL",)),
                  applied=(), failed=node("a"))
    d = orch.decide(sc)
    assert d.decision is Decision.HALT
    assert "NO_STATE_TO_ROLLBACK" in d.reasons


def test_manual_reversible_applied_state_halts(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("STAGE_FAIL",)),
                  applied=(node("a", reversibility=Reversibility.REVERSIBLE_MANUAL),))
    d = orch.decide(sc)
    assert d.decision is Decision.HALT
    assert "APPLIED_STATE_NOT_AUTO_REVERSIBLE" in d.reasons


# -------------------------------------------------------- evidence + format
def test_counts_and_causes_format_is_t4(orch):
    failure = Failure(cls=FailureClass.PARTIAL, causes=("ACK_MISSING", "CHECKSUM_BAD"), count=2, total=5)
    d = orch.decide(scenario(failure, applied=(node("a"),)))
    assert d.counts_and_causes.startswith("2/5 causes=")
    assert "ACK_MISSING" in d.counts_and_causes and "CHECKSUM_BAD" in d.counts_and_causes


def test_evidence_pair_matches_guard_2_8(orch):
    d = orch.decide(scenario(Failure(cls=FailureClass.BLOCKED, causes=("X",)),
                             applied=(node("a"),), failed=node("a")))
    decision_ev, report_ev = FailureOrchestrator.evidence_for_fsm2(d, "ev-d", "ev-r")
    assert decision_ev["kind"] == "failure_orchestrator:decision"
    assert report_ev["kind"] == "failure_report:counts_and_causes"
    assert decision_ev["detail"] == d.decision.value


def test_decision_is_deterministic(orch):
    sc = scenario(Failure(cls=FailureClass.BLOCKED, causes=("X",)),
                  applied=(node("a"), node("b")), failed=node("b"))
    assert orch.decide(sc) == orch.decide(sc)
