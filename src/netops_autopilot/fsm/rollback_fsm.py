"""FSM-3 Rollback — transitions & guards (D0-03 normative table, ADR-0009).

The READY conjunction mirrors rollback.schema.json preconditions 1:1; the
guard requires explicit evidence for EACH precondition — no shortcut, no
inference. Deploy engines read the state; they cannot mutate it except
through this machine.
"""

from __future__ import annotations

from typing import Any

from ..core.counters import CounterCollector
from .evidence import deny_missing, has_evidence, has_kinds
from .runtime import GuardOutcome, GuardedFsm, Transition, TransitionRecorder

FSM_LABEL = "FSM-3_ROLLBACK"
SCOPE = "CONFIGURATION"

# ------------------------------------------------------------------- states
INIT = "INIT"
NOT_SUPPORTED = "NOT_SUPPORTED"
NOT_CONFIGURED = "NOT_CONFIGURED"
NOT_READY = "NOT_READY"
READY = "READY"
ARMED = "ARMED"
CONFIRMED = "CONFIRMED"
ROLLBACK_TRIGGERED = "ROLLBACK_TRIGGERED"
ROLLBACK_SUCCEEDED = "ROLLBACK_SUCCEEDED"
ROLLBACK_FAILED = "ROLLBACK_FAILED"
UNKNOWN = "UNKNOWN"

ALL_STATES = frozenset({
    INIT, NOT_SUPPORTED, NOT_CONFIGURED, NOT_READY, READY, ARMED, CONFIRMED,
    ROLLBACK_TRIGGERED, ROLLBACK_SUCCEEDED, ROLLBACK_FAILED, UNKNOWN,
})

#: The §14 / ADR-0009 conjunction, evidence kinds named 1:1.
READY_PRECONDITIONS = (
    "precondition:MECHANISM_SUPPORTED_ON_VERSION",
    "precondition:ARTIFACT_EXISTS",
    "precondition:HASH_RECORDED",
    "precondition:FILESYSTEM_PREREQS",
    "precondition:TARGET_PRESERVES_MANAGEMENT_PATH",
    "precondition:ALL_COMMANDS_REVERSIBLE_BY_METHOD",
    "precondition:RECOVERY_PATH_VERIFIED",
)

# -------------------------------------------------------------------- guards
def g_3_1_not_supported(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="matrix:mechanism_absent")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("matrix:mechanism_absent (3.1)")


def g_3_2_not_configured(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="matrix:mechanism_supported")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("matrix:mechanism_supported (3.2)")


def g_3_3_not_ready(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="artifact:exists")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("artifact:exists (3.3)")


def g_3_4_ready(ctx: dict[str, Any]) -> GuardOutcome:
    """The full conjunction — every precondition evidenced individually."""
    found, missing = has_kinds(ctx, SCOPE, READY_PRECONDITIONS)
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (3.4)")


def g_3_5_armed(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="fsm2:ARMED_bound")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("fsm2:ARMED_bound (3.5)")


def g_3_6_confirmed(ctx: dict[str, Any]) -> GuardOutcome:
    found, missing = has_kinds(ctx, SCOPE, ("apply:ok", "verification_window:opened"))
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (3.6)")


def g_3_7_triggered(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="rollback:trigger_reason")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("rollback:trigger_reason (3.7)")


def g_3_8_succeeded(ctx: dict[str, Any]) -> GuardOutcome:
    """Post-trigger verification is mandatory (ADR-0009 §5)."""
    required = ("rollback:reapplied", "rollback:post_verify_pass", "mgmt_path:reachable")
    found, missing = has_kinds(ctx, SCOPE, required)
    return GuardOutcome.pass_with(*found) if not missing else deny_missing(", ".join(missing) + " (3.8)")


def g_3_9_failed(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="rollback:succeed_conjunct_failed")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("rollback:succeed_conjunct_failed (3.9)")


def g_3_10_unknown(ctx: dict[str, Any]) -> GuardOutcome:
    ids = has_evidence(ctx, SCOPE, kind="evidence:vanished")
    return GuardOutcome.pass_with(*ids) if ids else deny_missing("evidence:vanished (3.10)")


#: FSM-3 transition table (guard ids match D0-03).
ROLLBACK_TRANSITIONS: list[Transition] = [
    Transition(INIT, NOT_SUPPORTED, "3.1", g_3_1_not_supported),
    Transition(INIT, NOT_CONFIGURED, "3.2", g_3_2_not_configured),
    Transition(NOT_CONFIGURED, NOT_READY, "3.3", g_3_3_not_ready),
    Transition(NOT_READY, READY, "3.4", g_3_4_ready),
    Transition(READY, ARMED, "3.5", g_3_5_armed),
    Transition(ARMED, CONFIRMED, "3.6", g_3_6_confirmed),
    Transition(ARMED, ROLLBACK_TRIGGERED, "3.7", g_3_7_triggered),
    Transition(ROLLBACK_TRIGGERED, ROLLBACK_SUCCEEDED, "3.8", g_3_8_succeeded),
    Transition(ROLLBACK_TRIGGERED, ROLLBACK_FAILED, "3.9", g_3_9_failed),
    Transition(ARMED, UNKNOWN, "3.10", g_3_10_unknown),
    Transition(NOT_CONFIGURED, UNKNOWN, "3.10", g_3_10_unknown),
]


def build_rollback_fsm(recorder: TransitionRecorder, counters: CounterCollector) -> GuardedFsm:
    return GuardedFsm(
        fsm_label=FSM_LABEL,
        initial_state=INIT,
        transitions=ROLLBACK_TRANSITIONS,
        recorder=recorder,
        counters=counters,
    )
