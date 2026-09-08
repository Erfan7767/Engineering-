"""E17 Recovery Engine — drives FSM-5's escalation ladder (§14).

Recovery restores REACHABILITY (configuration is FSM-3's job). Rules:

* attempts are never faked: a level whose mechanism the matrix marks
  SUPPORTED requires a caller/adapter-supplied attempt outcome; the engine
  refuses to invent one (T2);
* matrix-skips are evidence-driven: NOT_SUPPORTED levels escalate on
  ``matrix:L{n}_not_supported``; L3 (OOB) defaults to NOT_CONFIGURED in v1
  when the matrix says UNKNOWN (ADR-0004), recorded — never hardcoded;
* entering L5 (bootloader tier) always requires a recorded human decision
  on the DESTRUCTIVE gate (L06, guard 5.4), in every autonomy mode;
* L6/L7 are physical tiers: the engine emits the wait-for-human path
  (5.5); exhausted paths end in LOST (5.6) — loss is a terminal, recorded
  state, never a silent retry loop.
"""

from __future__ import annotations

from typing import Optional

from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from ..fsm import recovery_fsm as rc
from ..ledger.models import OperatorIdentity
from .capability import CapabilityEngine, RecoveryStatus

SCOPE = rc.SCOPE
_RECOVERY_ACTOR = OperatorIdentity(kind="ENGINE", id="E17")

#: Level → recovery matrix mechanism (None = no matrix fact; the attempt
#: outcome must come from the caller/adapter).
LEVEL_MECHANISM = {
    0: None,                 # retry / settle
    1: None,                 # session re-establishment
    2: None,                 # configuration rollback (delegates to FSM-3)
    3: "oob",                # out-of-band path (site-dependent in v1)
    4: "console_recovery",   # serial console (direct-connect in v1 scope)
    5: "bootloader_recovery",
    6: None,                 # physical intervention (HUMAN_TASK)
    7: None,                 # vendor RMA / replacement (HUMAN_TASK)
}

#: Levels that physically destroy state — human-decided in every mode (L06).
DESTRUCTIVE_LEVELS = frozenset({5, 6, 7})

MAX_LEVEL = 7


class RecoveryEngine:
    def __init__(self, fsm, capability: CapabilityEngine, platform: str) -> None:
        self._fsm = fsm
        self._capability = capability
        self._platform = platform

    @property
    def state(self) -> str:
        return self._fsm.state

    # ------------------------------------------------------------------ start
    def start(self, device_ref: str, failure_evidence_id: str, change_id: str) -> None:
        if not failure_evidence_id or not change_id:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("RECOVERY_BINDING_INCOMPLETE: classified failure + bound change required (5.1)",))
        self._fire(rc.ESCALATING_L0, device_ref, [
            self._ev("failure:classified_recoverable", failure_evidence_id),
            self._ev("change:bound", change_id),
        ])

    # -------------------------------------------------------------- escalate
    def escalate(self, device_ref: str, level_from: int, *,
                 attempt_failed: Optional[bool] = None) -> None:
        """Move L{level_from} → L{level_from+1} with honest evidence."""
        if level_from < 0 or level_from >= MAX_LEVEL:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"RECOVERY_LEVEL_OUT_OF_RANGE:{level_from}",))
        if level_from == 4:
            # Entering the destructive tier has its own gate-checked path.
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("DESTRUCTIVE_GATE_REQUIRED: use escalate_into_destructive() with a recorded human decision (L06)",))
        if level_from == 0 and self.state != rc.ESCALATING_L0:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("RECOVERY_NOT_STARTED: call start() before escalating",))

        evidence: list[dict] = []
        mechanism = LEVEL_MECHANISM[level_from]
        if mechanism is not None:
            status = self._capability.recovery_lookup(self._platform, mechanism).status
            if status is RecoveryStatus.NOT_SUPPORTED:
                evidence.append(self._ev(f"matrix:L{level_from}_not_supported"))
            elif status is RecoveryStatus.UNKNOWN and level_from == 3:
                # ADR-0004 v1 default: OOB absent ⇒ recorded skip.
                evidence.append(self._ev(f"matrix:L{level_from}_not_configured"))
        if not evidence:
            # Matrix does not excuse this level — an attempt outcome is mandatory.
            if attempt_failed is None:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"ATTEMPT_RESULT_REQUIRED:L{level_from} — the engine never fabricates attempt outcomes (T2)",))
            if not attempt_failed:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"ATTEMPT_NOT_FAILED:L{level_from} — escalation evidence requires failure; success belongs to 5.3",))
            evidence.append(self._ev(f"attempt:L{level_from}_failed"))

        target = f"ESCALATING_L{level_from + 1}"
        self._fire(target, device_ref, evidence)

    def escalate_into_destructive(self, device_ref: str, human_decision: str) -> None:
        """L4 → L5 with the DESTRUCTIVE-gate human decision recorded."""
        if not human_decision:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("DESTRUCTIVE_GATE_REQUIRED: L5 entry needs a recorded human decision (5.4, L06)",))
        if self.state != rc.ESCALATING_L4:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"RECOVERY_STATE_NOT_L4: currently {self.state}",))
        evidence = [self._ev("attempt:L4_failed")]
        mechanism = LEVEL_MECHANISM[4]
        status = self._capability.recovery_lookup(self._platform, mechanism).status
        if status is RecoveryStatus.NOT_SUPPORTED:
            evidence = [self._ev("matrix:L4_not_supported")]
        evidence.append(self._ev("gate:DESTRUCTIVE_human_decision", human_decision))
        self._fire(rc.ESCALATING_L5, device_ref, evidence)

    # -------------------------------------------------------------- outcomes
    def recovered(self, device_ref: str, reachability_id: str, identity_id: str,
                  reclassification_id: str) -> None:
        self._fire(rc.RECOVERED, device_ref, [
            self._ev("device:reachable_again", reachability_id),
            self._ev("identity:reconfirmed", identity_id),
            self._ev("state:reclassified", reclassification_id),
        ])

    def human_required(self, device_ref: str, instructions_evidence_id: str) -> None:
        """Physical tiers (L6/L7): emit HUMAN_TASK instructions and wait."""
        if not instructions_evidence_id:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("HUMAN_TASK_INSTRUCTIONS_MISSING (5.5)",))
        self._fire(rc.HUMAN_REQUIRED, device_ref,
                   [self._ev("human_task:instructions_emitted", instructions_evidence_id)])

    def lost(self, device_ref: str, exhausted_evidence_id: str) -> None:
        if not exhausted_evidence_id:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("PATHS_EXHAUSTED_EVIDENCE_MISSING (5.6)",))
        self._fire(rc.LOST, device_ref,
                   [self._ev("paths:all_exhausted", exhausted_evidence_id)])

    # ------------------------------------------------------------- internal
    @staticmethod
    def _ev(kind: str, evidence_id: Optional[str] = None) -> dict:
        return {"scope": SCOPE, "kind": kind,
                "evidence_id": evidence_id or new_id(), "status": "OK"}

    def _fire(self, target: str, entity: str, evidence: list[dict]) -> None:
        result = self._fsm.fire(entity, target, {"evidence": evidence}, _RECOVERY_ACTOR)
        if not result.success:
            raise result.failure
