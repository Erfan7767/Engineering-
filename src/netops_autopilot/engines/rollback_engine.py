"""E16 Rollback Engine — drives FSM-3 with artifact-level honesty (ADR-0009).

Rollback restores CONFIGURATION (reachability is FSM-5's job). This engine:

* plans from the IR: mechanism candidates come from the Recovery Matrix
  only (SUPPORTED and non-destructive), chosen deterministically; any
  IRREVERSIBLE node makes the plan infeasible — never approximated;
* configures by firing guards 3.2→3.3→3.4, producing EACH §14 precondition
  as its own evidence item — the conjunction is evidence-checked, never
  shortcut; the artifact hash is RECOMPUTED at configure and again at
  trigger (trust nothing, verify everything);
* arms only against an FSM-2 ARMED binding (ADR-0009 §4);
* completes only on full post-verification (reapplied + post-verify PASS +
  management path reachable); any failed conjunct routes to
  ROLLBACK_FAILED with the failing conjuncts named — success is never
  claimed (L13).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from ..fsm import rollback_fsm as rf
from ..ledger.models import OperatorIdentity
from .capability import CapabilityEngine
from .config_ir import ConfigIR, Reversibility

SCOPE = rf.SCOPE
_ROLLBACK_ACTOR = OperatorIdentity(kind="ENGINE", id="E16")

#: Mechanisms that are recovery-of-last-resort, HUMAN_ONLY (§9). They are
#: never rollback candidates: rollback must preserve the device.
DESTRUCTIVE_MECHANISMS = frozenset({
    "netinstall", "rommon_reset", "factory_reset", "bootloader_recovery",
})


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@dataclass(frozen=True)
class RollbackArtifact:
    """Captured pre-change state. The hash is recomputed, never trusted."""

    mechanism: str
    content: bytes
    recorded_hash: str
    preserves_management_path: bool
    all_commands_reversible: bool
    filesystem_prereqs_ok: bool
    recovery_path_verified: bool
    captured_at: str  # injectable ISO-8601 (deterministic tests)

    def hash_ok(self) -> bool:
        return bool(self.content) and sha256_hex(self.content) == self.recorded_hash


@dataclass(frozen=True)
class RollbackPlan:
    platform: str
    mechanism: Optional[str]
    candidates: tuple[str, ...]  # supported, non-destructive, deterministic order
    node_sequence: tuple[str, ...]  # IR node ids, reverse application order
    feasible: bool
    blockers: tuple[str, ...]


class RollbackEngine:
    def __init__(self, fsm, capability: CapabilityEngine) -> None:
        self._fsm = fsm
        self._capability = capability

    # ------------------------------------------------------------------ plan
    def plan_from_ir(self, ir: ConfigIR, platform: str) -> RollbackPlan:
        from .capability import RecoveryStatus
        methods = self._capability.recovery_methods(platform)
        candidates = tuple(
            m for m in methods
            if m not in DESTRUCTIVE_MECHANISMS
            and self._capability.recovery_lookup(platform, m).status is RecoveryStatus.SUPPORTED
        )
        # Deterministic preference: a mechanism the matrix marks PRIMARY
        # (in its note) ranks first; ties break alphabetically.
        def preference(name: str) -> tuple[int, str]:
            note = self._capability.recovery_lookup(platform, name).note
            return (0 if "PRIMARY" in note.upper() else 1, name)
        candidates = tuple(sorted(candidates, key=preference))
        blockers: list[str] = []
        irreversible = tuple(sorted(n.node_id for n in ir.nodes
                                    if n.reversibility is Reversibility.IRREVERSIBLE))
        if irreversible:
            blockers.append(f"IRREVERSIBLE_NODES:{','.join(irreversible)}")
        if not candidates:
            blockers.append("NO_SUPPORTED_MECHANISM")
        return RollbackPlan(platform=platform,
                            mechanism=candidates[0] if candidates else None,
                            candidates=candidates,
                            node_sequence=tuple(n.node_id for n in reversed(ir.nodes)),
                            feasible=not blockers,
                            blockers=tuple(blockers))

    # ------------------------------------------------------------- configure
    def configure(self, plan: RollbackPlan, artifact: RollbackArtifact) -> None:
        """Drive INIT/NOT_SUPPORTED…READY with one evidence item per §14
        precondition. Fails closed on the first unmet conjunction."""
        from .capability import RecoveryStatus

        def ev(kind: str) -> dict:
            return {"scope": SCOPE, "kind": kind, "evidence_id": new_id(), "status": "OK"}

        if not plan.feasible or plan.mechanism is None:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"ROLLBACK_PLAN_INFEASIBLE:{';'.join(plan.blockers)}",))
        if artifact.mechanism != plan.mechanism:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"ARTIFACT_MECHANISM_MISMATCH: plan={plan.mechanism} artifact={artifact.mechanism}",))

        lookup = self._capability.recovery_lookup(plan.platform, plan.mechanism)
        if lookup.status is RecoveryStatus.NOT_SUPPORTED:
            self._fire(rf.NOT_SUPPORTED, [ev("matrix:mechanism_absent")], plan.platform)
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("ROLLBACK_NOT_SUPPORTED_BY_MATRIX",))
        if lookup.status is not RecoveryStatus.SUPPORTED:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"ROLLBACK_MECHANISM_UNKNOWN:{plan.mechanism} (T2: UNKNOWN never plans)",))

        # 3.2: supported on this platform; 3.3: artifact exists.
        self._fire(rf.NOT_CONFIGURED, [ev("matrix:mechanism_supported")], plan.platform)
        if not artifact.content:
            raise Failure(cls=FailureClass.BLOCKED, causes=("ARTIFACT_EMPTY",))
        self._fire(rf.NOT_READY, [ev("artifact:exists")], plan.platform)

        # 3.4: the full conjunction — every precondition evidenced, hash RECOMPUTED.
        unmet: list[str] = []
        if not artifact.hash_ok():
            unmet.append("HASH_RECORDED (recomputed sha256 mismatch)")
        if not artifact.filesystem_prereqs_ok:
            unmet.append("FILESYSTEM_PREREQS")
        if not artifact.preserves_management_path:
            unmet.append("TARGET_PRESERVES_MANAGEMENT_PATH")
        if not artifact.all_commands_reversible:
            unmet.append("ALL_COMMANDS_REVERSIBLE_BY_METHOD")
        if not artifact.recovery_path_verified:
            unmet.append("RECOVERY_PATH_VERIFIED")
        if unmet:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"ROLLBACK_PRECONDITIONS_UNMET:{';'.join(unmet)}",))
        evidence = [
            ev("precondition:MECHANISM_SUPPORTED_ON_VERSION"),
            ev("precondition:ARTIFACT_EXISTS"),
            ev("precondition:HASH_RECORDED"),
            ev("precondition:FILESYSTEM_PREREQS"),
            ev("precondition:TARGET_PRESERVES_MANAGEMENT_PATH"),
            ev("precondition:ALL_COMMANDS_REVERSIBLE_BY_METHOD"),
            ev("precondition:RECOVERY_PATH_VERIFIED"),
        ]
        self._fire(rf.READY, evidence, plan.platform)

    # ------------------------------------------------------------- lifecycle
    def arm(self, change_id: str, fsm2_arm_evidence_id: str) -> None:
        if not fsm2_arm_evidence_id:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("FSM2_ARM_BINDING_MISSING: rollback arms only against FSM-2 ARMED (ADR-0009)",))
        self._fire(rf.ARMED, [{"scope": SCOPE, "kind": "fsm2:ARMED_bound",
                               "evidence_id": fsm2_arm_evidence_id, "status": "OK"}], change_id)

    def confirm(self, change_id: str, apply_ok_id: str, window_id: str) -> None:
        self._fire(rf.CONFIRMED, [
            {"scope": SCOPE, "kind": "apply:ok", "evidence_id": apply_ok_id, "status": "OK"},
            {"scope": SCOPE, "kind": "verification_window:opened", "evidence_id": window_id, "status": "OK"},
        ], change_id)

    def trigger(self, change_id: str, reason: str, artifact: RollbackArtifact) -> None:
        if not reason:
            raise Failure(cls=FailureClass.BLOCKED, causes=("ROLLBACK_TRIGGER_REASON_EMPTY",))
        if not artifact.hash_ok():
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("ARTIFACT_HASH_MISMATCH: stored artifact changed since capture — refusing rollback",))
        self._fire(rf.ROLLBACK_TRIGGERED, [{"scope": SCOPE, "kind": "rollback:trigger_reason",
                                            "evidence_id": new_id(), "status": "OK"}], change_id)

    def complete(self, change_id: str, *, reapplied: bool, post_verify_pass: bool,
                 mgmt_reachable: bool) -> None:
        """Post-trigger verification is mandatory (ADR-0009 §5)."""
        conjuncts = {"reapplied": reapplied, "post_verify_pass": post_verify_pass,
                     "mgmt_reachable": mgmt_reachable}
        if all(conjuncts.values()):
            self._fire(rf.ROLLBACK_SUCCEEDED, [
                {"scope": SCOPE, "kind": "rollback:reapplied", "evidence_id": new_id(), "status": "OK"},
                {"scope": SCOPE, "kind": "rollback:post_verify_pass", "evidence_id": new_id(), "status": "OK"},
                {"scope": SCOPE, "kind": "mgmt_path:reachable", "evidence_id": new_id(), "status": "OK"},
            ], change_id)
            return
        failed = sorted(name for name, ok in conjuncts.items() if not ok)
        self._fire(rf.ROLLBACK_FAILED, [{"scope": SCOPE, "kind": "rollback:succeed_conjunct_failed",
                                         "evidence_id": new_id(), "status": "OK",
                                         "detail": ",".join(failed)}], change_id)

    # ------------------------------------------------------------- internal
    def _fire(self, target: str, evidence: list[dict], entity: str) -> None:
        result = self._fsm.fire(entity, target, {"evidence": evidence}, _ROLLBACK_ACTOR)
        if not result.success:
            raise result.failure
