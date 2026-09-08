"""FSM-4 Link / Physical Evidence — transitions & guards (D0-03 §FSM-4).

Encodes the epistemic ladder of §10 Link Evidence Fusion:
* passive evidence has a hard ceiling: DIRECT_NEIGHBOR_PROBABLE (4.5);
* CONFIRMED additionally requires proven absence of an intermediary (4.6);
* PHYSICAL_PATH_VERIFIED requires GATED active proof or explicit human
  confirmation with identity (4.7) — never inferred (L01);
* conflicts are terminal for automation: CONFLICTING has no outgoing
  transitions and is raised to the operator (4.3);
* staleness quarantines the bundle; revival requires 4.9 re-evaluation.
"""

from __future__ import annotations

from typing import Any

from ..core.counters import CounterCollector
from .evidence import deny_missing, has_evidence, has_kinds
from .runtime import GuardOutcome, GuardedFsm, Transition, TransitionRecorder

FSM_LABEL = "FSM-4_LINK"
SCOPE_NEIGHBOR = "DIRECT_NEIGHBOR"
SCOPE_PATH = "PHYSICAL_PATH"

# ------------------------------------------------------------------- states
UNKNOWN = "UNKNOWN"
INFERRED = "INFERRED"
ONE_SIDED = "ONE_SIDED"
CONFLICTING = "CONFLICTING"
INTERMEDIATE_SUSPECTED = "INTERMEDIATE_SUSPECTED"
DIRECT_NEIGHBOR_PROBABLE = "DIRECT_NEIGHBOR_PROBABLE"
DIRECT_NEIGHBOR_CONFIRMED = "DIRECT_NEIGHBOR_CONFIRMED"
PHYSICAL_PATH_VERIFIED = "PHYSICAL_PATH_VERIFIED"
STALE = "STALE"

ALL_STATES = frozenset({
    UNKNOWN, INFERRED, ONE_SIDED, CONFLICTING, INTERMEDIATE_SUSPECTED,
    DIRECT_NEIGHBOR_PROBABLE, DIRECT_NEIGHBOR_CONFIRMED,
    PHYSICAL_PATH_VERIFIED, STALE,
})

# -------------------------------------------------------------------- guards
def g_4_1_inferred(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:mac_arp_cooccurrence")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("passive:mac_arp_cooccurrence (4.1)")


def g_4_2_one_sided(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:neighbor_advertisement_one_side")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("passive:neighbor_advertisement_one_side (4.2)")


def g_4_3_conflicting(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:sources_disagree")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("passive:sources_disagree (4.3)")


def g_4_4_intermediate_suspected(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:intermediary_hints")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("passive:intermediary_hints (4.4)")


def g_4_5_probable(ctx: dict[str, Any]) -> GuardOutcome:
    """Passive ceiling: bidirectional match, or one-sided + clean MAC +
    port-name correlation + time correlation (all three required)."""
    bidir = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:bidirectional_match")
    if bidir:
        return GuardOutcome.pass_with(*bidir)
    required = (
        "passive:one_sided_plus_clean_mac",
        "passive:port_name_correlation",
        "passive:time_correlation",
    )
    found, missing = has_kinds(ctx, SCOPE_NEIGHBOR, required)
    if not missing:
        return GuardOutcome.pass_with(*found)
    return deny_missing(
        "bidirectional_match OR (one_sided_plus_clean_mac + port_name_correlation + time_correlation) (4.5)"
    )


def g_4_6_confirmed(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="passive:absence_of_intermediary_proven")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("passive:absence_of_intermediary_proven (4.6)")


def g_4_7_path_verified(ctx: dict[str, Any]) -> GuardOutcome:
    """Gated active proof OR explicit human confirmation — nothing else
    produces PHYSICAL_PATH_VERIFIED (§10, gate per §13)."""
    active = has_evidence(ctx, SCOPE_PATH, kind="active:gated_proof")
    human = has_evidence(ctx, SCOPE_PATH, kind="human:explicit_confirmation")
    ids = active or human
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("active:gated_proof | human:explicit_confirmation (4.7)")


def g_4_8_stale(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="freshness:holdtime_exceeded")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("freshness:holdtime_exceeded (4.8)")


def g_4_9_reevaluate(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE_NEIGHBOR, kind="reassessment:initiated")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("reassessment:initiated (4.9)")


#: FSM-4 transition table (guard ids match D0-03).
LINK_TRANSITIONS: list[Transition] = [
    Transition(UNKNOWN, INFERRED, "4.1", g_4_1_inferred),
    Transition(UNKNOWN, ONE_SIDED, "4.2", g_4_2_one_sided),
    Transition(UNKNOWN, CONFLICTING, "4.3", g_4_3_conflicting),
    Transition(UNKNOWN, INTERMEDIATE_SUSPECTED, "4.4", g_4_4_intermediate_suspected),
    Transition(INFERRED, DIRECT_NEIGHBOR_PROBABLE, "4.5", g_4_5_probable),
    Transition(ONE_SIDED, DIRECT_NEIGHBOR_PROBABLE, "4.5", g_4_5_probable),
    Transition(DIRECT_NEIGHBOR_PROBABLE, DIRECT_NEIGHBOR_CONFIRMED, "4.6", g_4_6_confirmed),
    Transition(DIRECT_NEIGHBOR_CONFIRMED, PHYSICAL_PATH_VERIFIED, "4.7", g_4_7_path_verified),
    Transition(DIRECT_NEIGHBOR_PROBABLE, PHYSICAL_PATH_VERIFIED, "4.7", g_4_7_path_verified),
    Transition(INFERRED, STALE, "4.8", g_4_8_stale),
    Transition(ONE_SIDED, STALE, "4.8", g_4_8_stale),
    Transition(DIRECT_NEIGHBOR_PROBABLE, STALE, "4.8", g_4_8_stale),
    Transition(DIRECT_NEIGHBOR_CONFIRMED, STALE, "4.8", g_4_8_stale),
    Transition(PHYSICAL_PATH_VERIFIED, STALE, "4.8", g_4_8_stale),
    Transition(STALE, UNKNOWN, "4.9", g_4_9_reevaluate),
]

#: CONFLICTING must have no outgoing transitions (operator-raised, never
#: auto-resolved). Enforced by test_link_fsm.
assert not any(t.from_state == CONFLICTING for t in LINK_TRANSITIONS)


def build_link_fsm(recorder: TransitionRecorder, counters: CounterCollector) -> GuardedFsm:
    return GuardedFsm(
        fsm_label=FSM_LABEL,
        initial_state=UNKNOWN,
        transitions=LINK_TRANSITIONS,
        recorder=recorder,
        counters=counters,
    )
