"""FSM-1 Device Lifecycle — transitions & guards (D0-03 normative table).

Guards are evidence-driven: each requires typed items in ``ctx["evidence"]``
(list of EvidenceItem). A guard never infers a missing fact (L01); absence
of the required evidence ⇒ deny.

Evidence item shape (dict):
    {"scope": <verification_scope>, "kind": <free string>,
     "evidence_id": <ledger id>, "status": "OK"|...}
"""

from __future__ import annotations

from typing import Any

from ..core.counters import CounterCollector
from ..ledger.models import OperatorIdentity
from .evidence import deny_missing as _deny_missing  # noqa: F401 (kept for callers)
from .evidence import has_evidence as _has  # noqa: F401
from .evidence import items as _items  # noqa: F401
from .runtime import GuardOutcome, GuardedFsm, Transition, TransitionRecorder

FSM_LABEL = "FSM-1_DEVICE"

UNKNOWN = "UNKNOWN"
PHYSICAL_DETECTED = "PHYSICAL_DETECTED"
ACCESSIBLE = "ACCESSIBLE"
IDENTIFIED = "IDENTIFIED"
BOOTSTRAP_REQUIRED = "BOOTSTRAP_REQUIRED"
BOOTSTRAPPED = "BOOTSTRAPPED"
DISCOVERED = "DISCOVERED"
MODELED = "MODELED"
MANAGED = "MANAGED"
ACCESS_LIMITED = "ACCESS_LIMITED"
PASSWORD_LOCKED = "PASSWORD_LOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
UNSUPPORTED = "UNSUPPORTED"
STALE = "STALE"

#: Fields required on DEVICE_IDENTITY evidence to consider identity resolved.
_IDENTITY_FIELDS = ("vendor", "model", "os", "version")


# --------------------------------------------------------------------- guards
def g_1_1_physical_detected(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "INTERFACE_EXISTENCE", kind="carrier_probe") or _has(ctx, "INTERFACE_EXISTENCE", kind="com_port") or _has(ctx, "DEVICE_IDENTITY", kind="mac_seen")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("carrier/COM/MAC probe (1.1)")


def g_1_2_accessible(ctx: dict[str, Any]) -> GuardOutcome:
    session = _has(ctx, "DEVICE_IDENTITY", kind="session_open")
    classifier = _has(ctx, "DEVICE_IDENTITY", kind="day0_classifier")
    if session and classifier:
        return GuardOutcome.pass_with(*(session + classifier))
    return _deny_missing("session_open + day0_classifier (1.2)")


def g_1_3_identified(ctx: dict[str, Any]) -> GuardOutcome:
    fields = set()
    ids = []
    for item in _items(ctx):
        if item.get("scope") == "DEVICE_IDENTITY" and item.get("kind", "").startswith("identity_field:"):
            if item.get("status", "OK") == "OK":
                fields.add(item["kind"].split(":", 1)[1])
                ids.append(str(item.get("evidence_id", "")))
    if fields.issuperset(_IDENTITY_FIELDS):
        return GuardOutcome.pass_with(*ids)
    return _deny_missing(f"identity fields {sorted(set(_IDENTITY_FIELDS) - fields)} (1.3)")


def g_1_4_bootstrap_required(ctx: dict[str, Any]) -> GuardOutcome:
    state = _has(ctx, "DEVICE_IDENTITY", kind="day0_state:FACTORY_DEFAULT") or _has(ctx, "DEVICE_IDENTITY", kind="day0_state:FACTORY_LIKE")
    no_mgmt = _has(ctx, "DEVICE_IDENTITY", kind="mgmt_plane_absent")
    if state and no_mgmt:
        return GuardOutcome.pass_with(*(state + no_mgmt))
    return _deny_missing("factory-like state + mgmt_plane_absent (1.4)")


def g_1_5_bootstrapped(ctx: dict[str, Any]) -> GuardOutcome:
    verified = _has(ctx, "CONFIGURATION", kind="bootstrap_change_verified")
    baseline = _has(ctx, "CONFIGURATION", kind="post_bootstrap_baseline_hashed")
    if verified and baseline:
        return GuardOutcome.pass_with(*(verified + baseline))
    return _deny_missing("bootstrap VERIFIED + baseline hashed (1.5)")


def g_1_6_discovered(ctx: dict[str, Any]) -> GuardOutcome:
    done = _has(ctx, "CONFIGURATION", kind="discovery_layers_terminal")
    return GuardOutcome.pass_with(*done) if done else _deny_missing("all discovery layers terminal (1.6)")


def g_1_7_modeled(ctx: dict[str, Any]) -> GuardOutcome:
    accepted = _has(ctx, "CONFIGURATION", kind="twin_claims_accepted")
    gaps = _has(ctx, "CONFIGURATION", kind="gaps_list_emitted")
    no_hallucination = not any(i.get("kind") == "entity_hallucination_flag" for i in _items(ctx))
    if accepted and gaps and no_hallucination:
        return GuardOutcome.pass_with(*(accepted + gaps))
    return _deny_missing("twin acceptance + gaps list + zero hallucination flags (1.7)")


def g_1_8_managed(ctx: dict[str, Any]) -> GuardOutcome:
    collectors = _has(ctx, "SERVICE_REACHABILITY", kind="monitoring_collectors_bound")
    baseline = _has(ctx, "CONFIGURATION", kind="reconciliation_baseline_stored")
    recovery = _has(ctx, "SERVICE_REACHABILITY", kind="recovery_path_not_lost")
    if collectors and baseline and recovery:
        return GuardOutcome.pass_with(*(collectors + baseline + recovery))
    return _deny_missing("collectors bound + baseline stored + recovery path != LOST (1.8)")


def g_1_9_access_limited(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "DEVICE_IDENTITY", kind="command_set_denied")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("denied/unsupported command evidence (1.9)")


def g_1_10_password_locked(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "DEVICE_IDENTITY", kind="auth_rejected")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("auth rejection evidence (1.10)")


def g_1_11_recovery_required(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "SERVICE_REACHABILITY", kind="reachability_timeout")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("reachability timeout evidence (1.11)")


def g_1_12_unsupported(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "DEVICE_IDENTITY", kind="capability_matrix_negative")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("capability matrix negative lookup (1.12)")


def g_1_13_stale(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "CONFIGURATION", kind="freshness_grace_exceeded")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("freshness grace violation (1.13)")


def g_1_14_cleared(ctx: dict[str, Any]) -> GuardOutcome:
    ids = _has(ctx, "DEVICE_IDENTITY", kind="blocking_condition_cleared")
    return GuardOutcome.pass_with(*ids) if ids else _deny_missing("new evidence clearing the block (1.14)")


#: FSM-1 transition table (ids match D0-03).
DEVICE_TRANSITIONS: list[Transition] = [
    Transition(UNKNOWN, PHYSICAL_DETECTED, "1.1", g_1_1_physical_detected),
    Transition(PHYSICAL_DETECTED, ACCESSIBLE, "1.2", g_1_2_accessible),
    Transition(ACCESSIBLE, IDENTIFIED, "1.3", g_1_3_identified),
    Transition(ACCESSIBLE, ACCESS_LIMITED, "1.9", g_1_9_access_limited),
    Transition(ACCESSIBLE, PASSWORD_LOCKED, "1.10", g_1_10_password_locked),
    Transition(IDENTIFIED, BOOTSTRAP_REQUIRED, "1.4", g_1_4_bootstrap_required),
    Transition(BOOTSTRAP_REQUIRED, BOOTSTRAPPED, "1.5", g_1_5_bootstrapped),
    Transition(IDENTIFIED, DISCOVERED, "1.6", g_1_6_discovered),
    Transition(IDENTIFIED, UNSUPPORTED, "1.12", g_1_12_unsupported),
    Transition(DISCOVERED, MODELED, "1.7", g_1_7_modeled),
    Transition(MODELED, MANAGED, "1.8", g_1_8_managed),
    Transition(MANAGED, STALE, "1.13", g_1_13_stale),
    Transition(STALE, MANAGED, "1.14", g_1_14_cleared),
    Transition(ACCESS_LIMITED, PHYSICAL_DETECTED, "1.14", g_1_14_cleared),
    Transition(PASSWORD_LOCKED, PHYSICAL_DETECTED, "1.14", g_1_14_cleared),
    Transition(UNKNOWN, RECOVERY_REQUIRED, "1.11", g_1_11_recovery_required),
    Transition(MANAGED, RECOVERY_REQUIRED, "1.11", g_1_11_recovery_required),
    Transition(RECOVERY_REQUIRED, PHYSICAL_DETECTED, "1.14", g_1_14_cleared),
]


def build_device_fsm(
    recorder: TransitionRecorder,
    counters: CounterCollector,
) -> GuardedFsm:
    return GuardedFsm(
        fsm_label=FSM_LABEL,
        initial_state=UNKNOWN,
        transitions=DEVICE_TRANSITIONS,
        recorder=recorder,
        counters=counters,
    )


__all__ = [
    "FSM_LABEL", "DEVICE_TRANSITIONS", "build_device_fsm", "GuardedFsm",
    "OperatorIdentity",
]
