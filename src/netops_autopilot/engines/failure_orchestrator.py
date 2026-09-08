"""E18 Failure Orchestrator — decides what happens after a stage failure
(FSM-2 guard 2.8, D0-01 §3 failure classes).

The decision space is exactly the spec's: CONTINUE / ISOLATE /
PARTIAL_ROLLBACK / FULL_ROLLBACK / HALT, always with recorded causes and
counts (T4: n/N + causes are mandatory evidence for the FAILED/PARTIAL
transitions).

Deterministic algebra, fail-safe ordered:
1. MANUAL_REQUIRED failures ⇒ HALT (physical/human tier, L06 territory);
2. any APPLIED node irreversible or destructive ⇒ HALT (automatic rollback
   is impossible; never pretend otherwise);
3. RETRYABLE with remaining budget ⇒ CONTINUE;
4. management-path impact ⇒ ISOLATE (contain before anything else);
5. PARTIAL-class failure with fully-replaceable applied state ⇒
   PARTIAL_ROLLBACK;
6. all applied REVERSIBLE_BY_REPLACE: tail-node failure ⇒ PARTIAL_ROLLBACK,
   stage-level failure ⇒ FULL_ROLLBACK; nothing applied ⇒ HALT (there is no
   state to undo — inventing a rollback would be fabrication);
7. anything else (REVERSIBLE_MANUAL present, FATAL, unclassified) ⇒ HALT.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..core.failures import Failure, FailureClass
from .config_ir import IRNode, Reversibility


class Decision(str, Enum):
    CONTINUE = "CONTINUE"
    ISOLATE = "ISOLATE"
    PARTIAL_ROLLBACK = "PARTIAL_ROLLBACK"
    FULL_ROLLBACK = "FULL_ROLLBACK"
    HALT = "HALT"


@dataclass(frozen=True)
class FailureScenario:
    change_id: str
    failure: Failure
    applied_nodes: tuple[IRNode, ...]
    failed_node: Optional[IRNode]
    remaining_nodes: tuple[IRNode, ...]
    attempts_used: int
    attempt_budget: int
    management_path_affected: bool

    @property
    def attempted_total(self) -> int:
        return len(self.applied_nodes) + (1 if self.failed_node is not None else 0)


@dataclass(frozen=True)
class OrchestratorDecision:
    decision: Decision
    failure_cls: FailureClass
    reasons: tuple[str, ...]
    count_failed: int
    count_total: int

    @property
    def counts_and_causes(self) -> str:
        """T4 format: n/N + causes, suitable as guard 2.8 evidence detail."""
        return f"{self.count_failed}/{self.count_total} causes={';'.join(self.reasons)}"


class FailureOrchestrator:
    """Pure decision function — no I/O, no counters, fully deterministic."""

    def decide(self, sc: FailureScenario) -> OrchestratorDecision:
        count_failed = sc.failure.count if sc.failure.cls is FailureClass.PARTIAL else 1
        count_total = sc.failure.total if sc.failure.cls is FailureClass.PARTIAL else max(sc.attempted_total, 1)

        def out(decision: Decision, *extra_reasons: str) -> OrchestratorDecision:
            reasons = tuple(extra_reasons) + tuple(sc.failure.causes)
            return OrchestratorDecision(decision=decision, failure_cls=sc.failure.cls,
                                        reasons=reasons, count_failed=count_failed,
                                        count_total=count_total)

        # 1. Physical/human tier failures are never continued automatically;
        #    FATAL (system-level) failures are never rolled back blindly.
        if sc.failure.cls is FailureClass.MANUAL_REQUIRED:
            return out(Decision.HALT, "MANUAL_REQUIRED_CLASS")
        if sc.failure.cls is FailureClass.FATAL:
            return out(Decision.HALT, "FATAL_CLASS: system-level failure — rollback cannot be trusted automatically")

        # 2. Irreversible/destructive applied state ⇒ automatic rollback impossible.
        stuck = tuple(sorted(n.node_id for n in sc.applied_nodes
                             if n.reversibility is Reversibility.IRREVERSIBLE or n.destructive))
        if stuck:
            return out(Decision.HALT, f"IRREVERSIBLE_APPLIED:{','.join(stuck)}")

        # 3. Retryable within budget ⇒ stay the course.
        if sc.failure.cls is FailureClass.RETRYABLE and sc.attempts_used < sc.attempt_budget:
            return out(Decision.CONTINUE,
                       f"RETRYABLE_BUDGET_REMAINING:{sc.attempts_used}/{sc.attempt_budget}")

        # 4. Contain management-path impact first.
        if sc.management_path_affected:
            return out(Decision.ISOLATE, "MANAGEMENT_PATH_IMPACT")

        # 5/6. Rollback decisions — automatic only over replaceable state.
        if any(n.reversibility is not Reversibility.REVERSIBLE_BY_REPLACE for n in sc.applied_nodes):
            return out(Decision.HALT, "APPLIED_STATE_NOT_AUTO_REVERSIBLE")
        if not sc.applied_nodes:
            return out(Decision.HALT, "NO_STATE_TO_ROLLBACK")
        if sc.failure.cls is FailureClass.PARTIAL:
            return out(Decision.PARTIAL_ROLLBACK, "PARTIAL_FAILURE_OVER_REPLACEABLE_STATE")
        if sc.failed_node is not None and sc.failed_node.node_id == sc.applied_nodes[-1].node_id:
            return out(Decision.PARTIAL_ROLLBACK, "TAIL_NODE_FAILURE")
        return out(Decision.FULL_ROLLBACK, "STAGE_LEVEL_FAILURE")

    # ------------------------------------------------- FSM-2 guard 2.8 feed
    @staticmethod
    def evidence_for_fsm2(decision: OrchestratorDecision,
                          evidence_decision_id: str, evidence_report_id: str) -> tuple[dict, dict]:
        """The exact pair guard 2.8 demands (FAILED and PARTIAL alike)."""
        return (
            {"scope": "CONFIGURATION", "kind": "failure_orchestrator:decision",
             "evidence_id": evidence_decision_id, "status": "OK",
             "detail": decision.decision.value},
            {"scope": "CONFIGURATION", "kind": "failure_report:counts_and_causes",
             "evidence_id": evidence_report_id, "status": "OK",
             "detail": decision.counts_and_causes},
        )
