"""Generic guarded FSM runtime (D0-03 runtime requirements).

Rules implemented here:
1. Every successful transition emits a StateTransition record via the
   injected recorder (the ledger).
2. Guard evaluation is pure & logged; an exception inside a guard denies
   the transition (fail-closed), never allows it.
3. Illegal transition attempts (no table entry) are audited and increment
   the ``gate_bypass`` T5 counter.
4. A guard denial is a normal BLOCKED outcome (NOT a bypass): the attempt
   is recorded with its failure, state is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, Protocol

from ..core.counters import CounterCollector
from ..core.failures import Failure, FailureClass
from ..core.timeauth import utc_now
from ..ledger.models import OperatorIdentity, StateTransition


@dataclass(frozen=True)
class GuardOutcome:
    """Result of evaluating one guard."""

    ok: bool
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""
    failure_class: Optional[FailureClass] = None

    @staticmethod
    def pass_with(*evidence_ids: str) -> "GuardOutcome":
        return GuardOutcome(ok=True, evidence_ids=tuple(evidence_ids))

    @staticmethod
    def deny(reason: str, failure_class: FailureClass = FailureClass.BLOCKED, evidence_ids: tuple[str, ...] = ()) -> "GuardOutcome":
        return GuardOutcome(ok=False, reason=reason, failure_class=failure_class, evidence_ids=evidence_ids)


Guard = Callable[[dict[str, Any]], GuardOutcome]


class TransitionRecorder(Protocol):
    def append_transition(self, tr: StateTransition) -> None: ...


@dataclass(frozen=True)
class Transition:
    from_state: str
    to_state: str
    guard_id: str
    guard: Guard


@dataclass
class FsmAttemptResult:
    success: bool
    new_state: str
    guard_id: str = ""
    evidence_ids: tuple[str, ...] = ()
    failure: Optional[Failure] = None
    illegal: bool = False


class GuardedFsm:
    """One FSM instance bound to an entity, with a static transition table."""

    def __init__(
        self,
        fsm_label: str,
        initial_state: str,
        transitions: list[Transition],
        recorder: TransitionRecorder,
        counters: CounterCollector,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.fsm_label = fsm_label
        self.state = initial_state
        if len({(t.from_state, t.to_state) for t in transitions}) != len(transitions):
            raise ValueError("duplicate transition definitions (spec defect)")
        self._table: dict[tuple[str, str], Transition] = {
            (t.from_state, t.to_state): t for t in transitions
        }
        self._recorder = recorder
        self._counters = counters
        self._clock = clock

    def allowed_targets(self) -> list[str]:
        return sorted(to for (frm, to) in self._table if frm == self.state)

    def fire(self, entity_ref: str, to_state: str, ctx: dict[str, Any], actor: OperatorIdentity) -> FsmAttemptResult:
        """Attempt a transition. Fail-closed on any guard exception."""
        key = (self.state, to_state)
        transition = self._table.get(key)
        if transition is None:
            # Illegal transition attempt: audited + counted (D0-03 rule 3).
            self._counters.increment(
                "gate_bypass",
                f"ILLEGAL_TRANSITION {self.fsm_label} {self.state}->{to_state} entity={entity_ref}",
            )
            return FsmAttemptResult(
                success=False, new_state=self.state, illegal=True,
                failure=Failure(
                    cls=FailureClass.BLOCKED,
                    causes=(f"ILLEGAL_TRANSITION: {self.state}->{to_state} has no table entry",),
                ),
            )

        try:
            outcome = transition.guard(ctx)
        except Exception as exc:  # fail-closed: guard crash ⇒ deny
            outcome = GuardOutcome.deny(f"GUARD_EXCEPTION: {exc!r}")

        if not outcome.ok:
            failure = Failure(
                cls=outcome.failure_class or FailureClass.BLOCKED,
                causes=(f"GUARD_{transition.guard_id}_DENIED: {outcome.reason}",),
                evidence_ids=outcome.evidence_ids,
            )
            return FsmAttemptResult(
                success=False, new_state=self.state, guard_id=transition.guard_id,
                evidence_ids=outcome.evidence_ids, failure=failure,
            )

        from_state = self.state
        self.state = to_state
        self._recorder.append_transition(
            StateTransition(
                fsm=self.fsm_label,
                entity_ref=entity_ref,
                from_state=from_state,
                to_state=to_state,
                guard_id=transition.guard_id,
                evidence_ids=list(outcome.evidence_ids) or ["guard:no-evidence-declared"],
                actor=actor,
                collected_at=self._clock(),
            )
        )
        return FsmAttemptResult(
            success=True, new_state=to_state, guard_id=transition.guard_id,
            evidence_ids=outcome.evidence_ids,
        )
