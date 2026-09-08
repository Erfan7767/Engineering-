"""FSM-2 Change Lifecycle — transitions & guards (D0-03 normative table).

Linearity: the main spine is DRAFT→VALIDATED→PLANNED→RISK_ASSESSED→
AUTHORIZED→ARMED→APPLYING→APPLIED→VERIFYING→VERIFIED→CLEANED→CLOSED;
branch states are reachable only through their listed guards. All guard ids
below match D0-03 §FSM-2 exactly.

Gate classes ride in ``ctx["gate_class"]`` (set by the caller from the
Autonomy Authority); the HUMAN_ONLY enforcement lives in guard 2.4 — no
policy content is interpreted here (separation per D0-02).
"""

from __future__ import annotations

from typing import Any

from ..core.counters import CounterCollector
from .evidence import deny_missing, has_evidence, has_kinds
from .runtime import GuardOutcome, GuardedFsm, Transition, TransitionRecorder

FSM_LABEL = "FSM-2_CHANGE"
SCOPE = "CONFIGURATION"

# ------------------------------------------------------------------- states
DRAFT = "DRAFT"
VALIDATED = "VALIDATED"
PLANNED = "PLANNED"
RISK_ASSESSED = "RISK_ASSESSED"
AUTHORIZED = "AUTHORIZED"
ARMED = "ARMED"
APPLYING = "APPLYING"
APPLIED = "APPLIED"
VERIFYING = "VERIFYING"
VERIFIED = "VERIFIED"
CLEANED = "CLEANED"
CLOSED = "CLOSED"
REJECTED = "REJECTED"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
ROLLED_BACK = "ROLLED_BACK"
RECOVERING = "RECOVERING"
MANUAL_REQUIRED = "MANUAL_REQUIRED"

ALL_STATES = frozenset({
    DRAFT, VALIDATED, PLANNED, RISK_ASSESSED, AUTHORIZED, ARMED, APPLYING,
    APPLIED, VERIFYING, VERIFIED, CLEANED, CLOSED, REJECTED, PARTIAL,
    FAILED, ROLLED_BACK, RECOVERING, MANUAL_REQUIRED,
})

HUMAN_ONLY_GATES = ("IRREVERSIBLE", "DESTRUCTIVE")
MFA_GATES = ("HIGH_RISK", "IRREVERSIBLE", "DESTRUCTIVE")

# -------------------------------------------------------------------- guards
def g_2_1_validated(ctx: dict[str, Any]) -> GuardOutcome:
    """Full Validation Fabric pass; NOT_MODELED recorded, never PASSED over."""
    ids = has_evidence(ctx, SCOPE, kind="validation_fabric:PASS")
    if not ids:
        return deny_missing("validation_fabric:PASS (2.1)")
    not_modeled = has_evidence(ctx, SCOPE, kind="validation_fabric:NOT_MODELED")
    if not_modeled and not has_evidence(ctx, SCOPE, kind="validation_fabric:not_modeled_recorded"):
        return GuardOutcome.deny("NOT_MODELED features present but not recorded (L13: NOT_MODELED != PASS)")
    return GuardOutcome.pass_with(*ids)


def g_2_2_planned(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("dag:total_order", "dag:permanent_constraints_ok"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.2)")


def g_2_3_risk_assessed(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("blast_radius:recorded", "risk_class:recorded"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.3)")


def g_2_4_authorized(ctx: dict[str, Any]) -> GuardOutcome:
    """Decision Readiness all-true + gate verdict + identity-bound approvals."""
    required = ["readiness:all_true", "gate_verdict:ALLOW"]
    gate_class = str(ctx.get("gate_class", ""))
    if not gate_class:
        return GuardOutcome.deny("gate_class absent from decision context (2.4)")
    if gate_class in MFA_GATES:
        required.append("approval:rbac_identity")
        required.append("approval:mfa_verified")
    if gate_class in HUMAN_ONLY_GATES:
        required.append("gate_verdict:HUMAN_DECIDED")
    found, missing = has_kinds(ctx, SCOPE, tuple(required))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + f" (2.4, gate={gate_class})")


def g_2_5_armed(ctx: dict[str, Any]) -> GuardOutcome:
    """ADR-0009: FSM-3 READY is a hard precondition of ARMED."""
    required = (
        "window:valid", "scheduler:no_conflict", "lock:acquirable",
        "rollback:READY", "scope_lock:recorded",
    )
    found, missing = has_kinds(ctx, SCOPE, required)
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.5)")


def g_2_6_applying(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("authorized_state:reverified", "allowlist:rechecked"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.6)")


def g_2_7_applied(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="apply:all_stages_ack")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("apply:all_stages_ack (2.7)")


def g_2_8_failed(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="failure_orchestrator:decision")
    if not ids:
        return deny_missing("failure_orchestrator:decision (2.8)")
    if not has_evidence(ctx, SCOPE, kind="failure_report:counts_and_causes"):
        return deny_missing("failure_report:counts_and_causes (T4)")
    return GuardOutcome.pass_with(*ids)


def g_2_8_partial(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="failure_orchestrator:decision")
    if not ids:
        return deny_missing("failure_orchestrator:decision (2.8)")
    if not has_evidence(ctx, SCOPE, kind="failure_report:counts_and_causes"):
        return deny_missing("failure_report:counts_and_causes (T4: n/N + causes mandatory)")
    return GuardOutcome.pass_with(*ids)


def g_2_9_verifying(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="apply:settled")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("apply:settled (2.9)")


def g_2_10_verified(ctx: dict[str, Any]) -> GuardOutcome:
    """PASS semantics: all-pass, or per-non-PASS documented human acceptance."""
    all_pass = has_evidence(ctx, SCOPE, kind="tests:all_pass")
    if all_pass:
        return GuardOutcome.pass_with(*all_pass)
    non_pass = has_evidence(ctx, SCOPE, kind="tests:non_pass_present")
    acceptance = has_evidence(ctx, SCOPE, kind="tests:human_acceptance_per_non_pass")
    if non_pass and acceptance:
        return GuardOutcome.pass_with(*(non_pass + acceptance))
    return deny_missing("tests:all_pass OR (tests:non_pass_present + tests:human_acceptance_per_non_pass) (2.10)")


def g_2_11_rolled_back(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("rollback:TRIGGERED", "rollback:SUCCEEDED"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.11)")


def g_2_11_recovering(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("rollback:TRIGGERED", "rollback:FAILED"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.11)")


def g_2_12_cleaned(ctx: dict[str, Any]) -> GuardOutcome:
    zero = has_evidence(ctx, SCOPE, kind="temp_resources:zero")
    preserved = has_evidence(ctx, SCOPE, kind="temp_resources:preserved_by_approval")
    ids = zero or preserved
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("temp_resources:zero | :preserved_by_approval (2.12)")


def g_2_13_closed(ctx: dict[str, Any]) -> GuardOutcome:
    required = ("twin:refreshed_from_observed", "docs:emitted", "audit:chain_complete")
    found, missing = has_kinds(ctx, SCOPE, required)
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (2.13)")


def g_2_14_rejected(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="verdict:REJECTED")
    if not ids:
        return deny_missing("verdict:REJECTED with reason + evidence (2.14)")
    if not has_evidence(ctx, SCOPE, kind="verdict:reason_recorded"):
        return deny_missing("verdict:reason_recorded (2.14)")
    return GuardOutcome.pass_with(*ids)


def g_2_15_manual_required(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="human_task:instructions_emitted")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("human_task:instructions_emitted (2.15)")


#: FSM-2 transition table (guard ids match D0-03).
CHANGE_TRANSITIONS: list[Transition] = [
    Transition(DRAFT, VALIDATED, "2.1", g_2_1_validated),
    Transition(VALIDATED, PLANNED, "2.2", g_2_2_planned),
    Transition(PLANNED, RISK_ASSESSED, "2.3", g_2_3_risk_assessed),
    Transition(RISK_ASSESSED, AUTHORIZED, "2.4", g_2_4_authorized),
    Transition(AUTHORIZED, ARMED, "2.5", g_2_5_armed),
    Transition(ARMED, APPLYING, "2.6", g_2_6_applying),
    Transition(APPLYING, APPLIED, "2.7", g_2_7_applied),
    Transition(APPLYING, FAILED, "2.8", g_2_8_failed),
    Transition(APPLYING, PARTIAL, "2.8", g_2_8_partial),
    Transition(APPLIED, VERIFYING, "2.9", g_2_9_verifying),
    Transition(VERIFYING, VERIFIED, "2.10", g_2_10_verified),
    Transition(VERIFYING, ROLLED_BACK, "2.11", g_2_11_rolled_back),
    Transition(VERIFYING, RECOVERING, "2.11", g_2_11_recovering),
    Transition(VERIFIED, CLEANED, "2.12", g_2_12_cleaned),
    Transition(CLEANED, CLOSED, "2.13", g_2_13_closed),
    # 2.14 rejection is available from every pre-apply state.
    Transition(DRAFT, REJECTED, "2.14", g_2_14_rejected),
    Transition(VALIDATED, REJECTED, "2.14", g_2_14_rejected),
    Transition(PLANNED, REJECTED, "2.14", g_2_14_rejected),
    Transition(RISK_ASSESSED, REJECTED, "2.14", g_2_14_rejected),
    Transition(AUTHORIZED, REJECTED, "2.14", g_2_14_rejected),
    # 2.15 manual escalation from post-apply failure branches.
    Transition(FAILED, MANUAL_REQUIRED, "2.15", g_2_15_manual_required),
    Transition(PARTIAL, MANUAL_REQUIRED, "2.15", g_2_15_manual_required),
]


def build_change_fsm(recorder: TransitionRecorder, counters: CounterCollector) -> GuardedFsm:
    return GuardedFsm(
        fsm_label=FSM_LABEL,
        initial_state=DRAFT,
        transitions=CHANGE_TRANSITIONS,
        recorder=recorder,
        counters=counters,
    )
