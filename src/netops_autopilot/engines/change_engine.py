"""E15 Change Engine — drives FSM-2 through the decision spine (D0-03).

Wires the real engines to the real guards, in order:

    2.1 fabric   → VALIDATED
    2.2 DAG      → PLANNED
    2.3 blast    → RISK_ASSESSED
    2.4 autonomy → AUTHORIZED

Each step produces Ledger-grade evidence items whose ``kind`` strings are
exactly the kinds the corresponding guard demands; a refused transition
stops the pipeline with typed reasons — never silently, never partially
(L03). Guards 2.5 onward (arming, applying, verifying) belong to the
execution batches and are not faked here: a PreparedChange stops at
AUTHORIZED and reports that state honestly.

VETO (D0-02 rule 2) is available pre-APPLYING and terminates the change
into REJECTED; only a new change object can restart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.counters import CounterCollector
from ..core.ids import new_id
from ..fsm import change_fsm as cf
from ..ledger.models import OperatorIdentity
from ..policy import authority as auth
from .autonomy import Approval, AutonomyAuthority, DecisionReadiness, Verdict
from .blast_radius import BlastRadiusEngine, BlastReport
from .config_ir import ConfigIR
from .dependency_dag import DAGPlan, DependencyDAGEngine
from .validation_fabric import FabricVerdict, PolicyContext, StageStatus, ValidationFabric

SCOPE = cf.SCOPE

_ENGINE_ACTOR = OperatorIdentity(kind="ENGINE", id="E15")


@dataclass(frozen=True)
class PreparedChange:
    change_id: str
    ir_id: str
    final_state: str
    blocked_reasons: tuple[str, ...]
    evidence: tuple[dict, ...]
    decision: Optional[object] = None   # AutonomyDecision once reached
    plan: Optional[DAGPlan] = None
    blast: Optional[BlastReport] = None


class ChangeEngine:
    def __init__(self, *, fsm, fabric: ValidationFabric, dag: DependencyDAGEngine,
                 blast: BlastRadiusEngine, autonomy: AutonomyAuthority,
                 counters: CounterCollector) -> None:
        self._fsm = fsm
        self._fabric = fabric
        self._dag = dag
        self._blast = blast
        self._autonomy = autonomy
        self._counters = counters

    # --------------------------------------------------------------- prepare
    def prepare(self, change_id: str, ir: ConfigIR, *, policy: Optional[PolicyContext],
                device_versions, readiness: DecisionReadiness,
                external_provides: frozenset[str] = frozenset(),
                approval: Optional[Approval] = None) -> PreparedChange:
        evidence: list[dict] = []

        def ev(kind: str) -> dict:
            item = {"scope": SCOPE, "kind": kind, "evidence_id": new_id(), "status": "OK"}
            evidence.append(item)
            return item

        def fire(target: str, ctx: dict) -> None:
            result = self._fsm.fire(change_id, target, ctx, _ENGINE_ACTOR)
            if not result.success:
                raise result.failure

        # ---- 2.1 Validation Fabric --------------------------------------
        fabric_result = self._fabric.run(ir, policy=policy, device_versions=device_versions,
                                         external_provides=external_provides)
        if fabric_result.verdict is not FabricVerdict.PASS:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  (f"FABRIC_{fabric_result.verdict.value}",), tuple(evidence))
        ev("validation_fabric:PASS")
        if fabric_result.preflight_status is StageStatus.NOT_MODELED:
            ev("validation_fabric:NOT_MODELED")
            ev("validation_fabric:not_modeled_recorded")  # recorded, never passed over (L13)
        fire(cf.VALIDATED, {"evidence": list(evidence)})

        # ---- 2.2 Dependency DAG ------------------------------------------
        # Defense in depth: the fabric's DEPENDENCY stage validates tokens,
        # but service-level ordering (P1-34) is decided here. A typed DAG
        # failure blocks the change at VALIDATED with its exact causes.
        from ..core.failures import Failure as _Failure
        try:
            plan = self._dag.build(ir, external_provides=external_provides)
        except _Failure as failure:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  failure.causes, tuple(evidence))
        ev("dag:total_order")
        ev("dag:permanent_constraints_ok")
        fire(cf.PLANNED, {"evidence": list(evidence)})

        # ---- 2.3 Blast Radius ---------------------------------------------
        blast = self._blast.evaluate(ir)
        ev("blast_radius:recorded")
        ev("risk_class:recorded")
        fire(cf.RISK_ASSESSED, {"evidence": list(evidence)})

        # ---- 2.4 Autonomy Authority ----------------------------------------
        decision = self._autonomy.decide(
            gate_class=ir.gate_class(), risk_class=blast.risk_class,
            preflight_not_modeled=(fabric_result.preflight_status is StageStatus.NOT_MODELED),
            approval=approval)
        if decision.verdict is Verdict.BLOCKED:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  tuple(decision.reasons), tuple(evidence),
                                  decision=decision, plan=plan, blast=blast)
        if not readiness.all_true:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  (f"READINESS_NOT_ALL_TRUE:{','.join(readiness.false_conjuncts())}",),
                                  tuple(evidence), decision=decision, plan=plan, blast=blast)
        ev("readiness:all_true")
        if decision.verdict is Verdict.APPROVAL_REQUIRED and not decision.approval_satisfied:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  tuple(decision.reasons), tuple(evidence),
                                  decision=decision, plan=plan, blast=blast)
        if decision.verdict is Verdict.HUMAN_ONLY and not decision.human_decided:
            return PreparedChange(change_id, ir.ir_id, self._fsm.state,
                                  tuple(decision.reasons), tuple(evidence),
                                  decision=decision, plan=plan, blast=blast)
        # Guard 2.4 demands identity-bound approval evidence for MFA gates
        # (HIGH_RISK and every human-only gate). Evidence is emitted ONLY
        # when the facts hold — a false MFA record would violate T1.
        if approval is not None and approval.mfa_verified and decision.gate_class in cf.MFA_GATES:
            ev("approval:rbac_identity")
            ev("approval:mfa_verified")
        if decision.verdict is Verdict.HUMAN_ONLY:
            ev("gate_verdict:HUMAN_DECIDED")
        if decision.verdict is Verdict.AUTO_EXECUTE or decision.approval_satisfied:
            ev("gate_verdict:ALLOW")
        fire(cf.AUTHORIZED, {"evidence": list(evidence), "gate_class": decision.gate_class})

        return PreparedChange(change_id, ir.ir_id, self._fsm.state, (), tuple(evidence),
                              decision=decision, plan=plan, blast=blast)

    # ------------------------------------------------------------------ veto
    def veto(self, change_id: str, actor: str, reason: str, evidence_ids) -> None:
        """D0-02 rule 2: final rejection. Legal from any pre-APPLYING state."""
        auth.veto(change_id, actor, reason, evidence_ids)  # validates identity + reason
        evidence = [
            {"scope": SCOPE, "kind": "verdict:REJECTED", "evidence_id": new_id(), "status": "OK"},
            {"scope": SCOPE, "kind": "verdict:reason_recorded", "evidence_id": new_id(), "status": "OK"},
        ]
        result = self._fsm.fire(change_id, cf.REJECTED, {"evidence": evidence}, _ENGINE_ACTOR)
        if not result.success:
            raise result.failure
        # A lawful veto increments no counter: it is the system working as
        # designed (D0-02 rule 2). Its trace lives in the Ledger transition.
