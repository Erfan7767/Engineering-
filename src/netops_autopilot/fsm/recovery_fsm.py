"""FSM-5 Recovery Hierarchy — transitions & guards (D0-03 §FSM-5).

Independent of Rollback (FSM-3): recovery restores *reachability*, rollback
restores *configuration*. Levels L0..L7 per §14; entering L5 (bootloader /
destructive tier) always requires the DESTRUCTIVE gate with a human
decision, in every Autonomy Mode (L06, FSM-5 guard 5.4).

v1 note (ADR-0004): L3 (OOB) is typically NOT_CONFIGURED — the escalation
skip is evidence-driven via ``matrix:L3_not_configured`` and recorded, not
hardcoded as vendor behavior.
"""

from __future__ import annotations

from typing import Any

from ..core.counters import CounterCollector
from .evidence import deny_missing, has_evidence, has_kinds
from .runtime import GuardOutcome, GuardedFsm, Transition, TransitionRecorder

FSM_LABEL = "FSM-5_RECOVERY"
SCOPE = "SERVICE_REACHABILITY"

# ------------------------------------------------------------------- states
NOT_NEEDED = "NOT_NEEDED"
ESCALATING_L0 = "ESCALATING_L0"
ESCALATING_L1 = "ESCALATING_L1"
ESCALATING_L2 = "ESCALATING_L2"
ESCALATING_L3 = "ESCALATING_L3"
ESCALATING_L4 = "ESCALATING_L4"
ESCALATING_L5 = "ESCALATING_L5"
ESCALATING_L6 = "ESCALATING_L6"
ESCALATING_L7 = "ESCALATING_L7"
RECOVERED = "RECOVERED"
HUMAN_REQUIRED = "HUMAN_REQUIRED"
LOST = "LOST"

ALL_STATES = frozenset({
    NOT_NEEDED, ESCALATING_L0, ESCALATING_L1, ESCALATING_L2, ESCALATING_L3,
    ESCALATING_L4, ESCALATING_L5, ESCALATING_L6, ESCALATING_L7,
    RECOVERED, HUMAN_REQUIRED, LOST,
})

#: Level ladder, used to build escalation transitions mechanically.
_LEVELS: tuple[str, ...] = (
    ESCALATING_L0, ESCALATING_L1, ESCALATING_L2, ESCALATING_L3,
    ESCALATING_L4, ESCALATING_L5, ESCALATING_L6, ESCALATING_L7,
)


def _level_index(state: str) -> int:
    return _LEVELS.index(state)


# -------------------------------------------------------------------- guards
def g_5_1_escalating_l0(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("failure:classified_recoverable", "change:bound"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (5.1)")


def _g_5_2_step(level_from: int):
    """Escalation guard for L{n} → L{n+1}: attempt failed OR matrix says the
    level is NOT_SUPPORTED/NOT_CONFIGURED on this model (skip is recorded)."""

    def guard(ctx: dict[str, Any]) -> GuardOutcome:
        kinds = (
            f"attempt:L{level_from}_failed",
            f"matrix:L{level_from}_not_supported",
            f"matrix:L{level_from}_not_configured",
        )
        for kind in kinds:
            ids = has_evidence(ctx, SCOPE, kind=kind)
            if ids:
                return GuardOutcome.pass_with(*ids)
        return deny_missing(" | ".join(kinds) + f" (5.2 for L{level_from})")

    return guard


def _g_5_3_recovered(ctx: dict[str, Any]) -> GuardOutcome:
    """Reachability restored AND identity re-confirmed AND state re-classified."""
    required = ("device:reachable_again", "identity:reconfirmed", "state:reclassified")
    found, missing = has_kinds(ctx, SCOPE, required)
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (5.3)")


def _g_5_4_into_l5(ctx: dict[str, Any]) -> GuardOutcome:
    """L4 → L5: normal 5.2 evidence PLUS the DESTRUCTIVE gate with a human
    decision (HUMAN_ONLY, every mode)."""
    base = _g_5_2_step(4)(ctx)
    if not base.ok:
        return base
    gate = has_evidence(ctx, SCOPE, kind="gate:DESTRUCTIVE_human_decision")
    if not gate:
        return GuardOutcome.deny("gate:DESTRUCTIVE_human_decision required to enter L5 (5.4, L06)")
    return GuardOutcome.pass_with(*base.evidence_ids, *gate)


def _g_5_5_human_required(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="human_task:instructions_emitted")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("human_task:instructions_emitted (5.5)")


def _g_5_6_lost(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="paths:all_exhausted")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("paths:all_exhausted (5.6)")


def _build_transitions() -> list[Transition]:
    transitions: list[Transition] = [Transition(NOT_NEEDED, ESCALATING_L0, "5.1", g_5_1_escalating_l0)]

    # 5.2 escalation ladder (L4→L5 carries the extra 5.4 conjunction).
    for index in range(len(_LEVELS) - 1):
        guard = _g_5_4_into_l5 if index == 4 else _g_5_2_step(index)
        transitions.append(Transition(_LEVELS[index], _LEVELS[index + 1], "5.2", guard))

    # 5.3 recovery from any escalation level and from HUMAN_REQUIRED.
    for level in _LEVELS:
        transitions.append(Transition(level, RECOVERED, "5.3", _g_5_3_recovered))
    transitions.append(Transition(HUMAN_REQUIRED, RECOVERED, "5.3", _g_5_3_recovered))

    # 5.5 physical/human tiers emit instructions and wait.
    transitions.append(Transition(ESCALATING_L6, HUMAN_REQUIRED, "5.5", _g_5_5_human_required))
    transitions.append(Transition(ESCALATING_L7, HUMAN_REQUIRED, "5.5", _g_5_5_human_required))

    # 5.6 exhausted paths ⇒ LOST.
    for level in _LEVELS:
        transitions.append(Transition(level, LOST, "5.6", _g_5_6_lost))

    return transitions


RECOVERY_TRANSITIONS: list[Transition] = _build_transitions()


def build_recovery_fsm(recorder: TransitionRecorder, counters: CounterCollector) -> GuardedFsm:
    return GuardedFsm(
        fsm_label=FSM_LABEL,
        initial_state=NOT_NEEDED,
        transitions=RECOVERY_TRANSITIONS,
        recorder=recorder,
        counters=counters,
    )
