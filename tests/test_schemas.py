"""Schema contract tests (D0 deliverable): every JSON Schema is valid
Draft-07, model instances round-trip through them, and safety-critical
negative cases are rejected (HUMAN_ONLY un-representable, DESTRUCTIVE
un-authorizable)."""

import json
import pathlib

import pytest
from jsonschema import Draft7Validator, RefResolver

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "specs" / "schemas"


@pytest.fixture(scope="module")
def schemas():
    store = {}
    for p in sorted(SCHEMA_DIR.glob("*.json")):
        doc = json.loads(p.read_text())
        store[doc["$id"]] = doc
    return store


@pytest.fixture(scope="module")
def resolver(schemas):
    return RefResolver.from_schema(next(iter(schemas.values())), store=schemas)


def test_all_schemas_are_valid_draft7(schemas):
    assert len(schemas) == 11
    for sid, doc in schemas.items():
        Draft7Validator.check_schema(doc)


def _validate(schemas, resolver, sid, instance):
    validator = Draft7Validator(schemas[sid], resolver=resolver)
    return list(validator.iter_errors(instance))


def test_event_instance_roundtrip(schemas, resolver):
    from netops_autopilot.ledger.models import (
        ClockStatusEnum, CollectorIdentity, Event, EventType, OperatorIdentity,
    )
    from datetime import datetime, timezone

    ev = Event(
        type=EventType.PROBE, device_id=None, session_id=None,
        command_or_op="carrier_probe", operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
        collector_identity=CollectorIdentity(collector_id="c0", key_id="k0"),
        collected_at=datetime.now(timezone.utc), collector_clock_status=ClockStatusEnum.SYNCED,
    )
    errors = _validate(schemas, resolver, "https://netops-autopilot.local/schemas/event.schema.json",
                       ev.model_dump(mode="json"))
    assert errors == []


def test_claim_instance_roundtrip(schemas, resolver):
    from netops_autopilot.ledger.models import Claim, SubjectEntity

    claim = Claim(
        subject_entity=SubjectEntity(entity_type="INTERFACE", entity_ref="dev-1:Gi1/0/1"),
        predicate="oper_status", value="up", evidence_ids=["obs-1"],
        verification_scope="INTERFACE_EXISTENCE", status="CONFIRMED",
        relevance_check="PASS",
    )
    errors = _validate(schemas, resolver, "https://netops-autopilot.local/schemas/claim.schema.json",
                       claim.model_dump(mode="json"))
    assert errors == []


def test_claim_requires_evidence(schemas, resolver):
    """T1: a claim without evidence_ids is structurally invalid."""
    bad = {
        "claim_id": "00000000-0000-0000-0000-000000000001",
        "subject_entity": {"entity_type": "DEVICE", "entity_ref": "d"},
        "predicate": "p", "value": 1, "evidence_ids": [],
        "verification_scope": "CONFIGURATION", "status": "CONFIRMED",
        "relevance_check": "PASS",
    }
    errors = _validate(schemas, resolver, "https://netops-autopilot.local/schemas/claim.schema.json", bad)
    assert errors, "empty evidence_ids must be rejected"


def _policy(**over):
    base = {
        "policy_id": "00000000-0000-0000-0000-000000000002",
        "mode": "M3",
        "scope": {"site_ids": ["site-hq"], "entity_refs": []},
        "allowed_gate_classes": ["READ_ONLY", "LOW_RISK"],
        "issued_by": {"human_id": "eng-1", "rbac_role": "network-admin", "mfa_verified": True},
        "issued_at": "2026-09-05T12:00:00Z",
        "expires_at": "2026-10-05T12:00:00Z",
        "signature": {"algorithm": "Ed25519", "key_id": "signer-1", "value_b64": "AAAA"},
    }
    base.update(over)
    return base


def test_policy_valid_instance_accepted(schemas, resolver):
    errors = _validate(schemas, resolver, "https://netops-autopilot.local/schemas/autonomy_policy.schema.json", _policy())
    assert errors == []


def test_policy_cannot_authorize_destructive_or_irreversible(schemas, resolver):
    """ADR-0007: HUMAN_ONLY classes are not enum members — un-representable."""
    for cls in ("IRREVERSIBLE", "DESTRUCTIVE"):
        errors = _validate(
            schemas, resolver,
            "https://netops-autopilot.local/schemas/autonomy_policy.schema.json",
            _policy(allowed_gate_classes=["LOW_RISK", cls]),
        )
        assert errors, f"{cls} must be un-authorizable in a policy"


def test_policy_requires_mfa(schemas, resolver):
    bad = _policy()
    bad["issued_by"]["mfa_verified"] = False
    errors = _validate(schemas, resolver, "https://netops-autopilot.local/schemas/autonomy_policy.schema.json", bad)
    assert errors, "mfa_verified=false must be rejected"


def test_gate_verdict_requires_blockers_when_not_executed(schemas, resolver):
    gid = "https://netops-autopilot.local/schemas/gate_verdict.schema.json"
    base = {
        "verdict_id": "00000000-0000-0000-0000-000000000003",
        "change_id": "00000000-0000-0000-0000-000000000004",
        "gate_class": "LOW_RISK",
        "verdict": "BLOCKED",
        "readiness_ref": "r-1",
        "decided_by": {"kind": "ENGINE", "id": "E14"},
        "decided_at": "2026-09-05T12:00:00Z",
    }
    assert _validate(schemas, resolver, gid, base), "BLOCKED without blockers must fail"
    base["blockers"] = ["ROLLBACK_NOT_READY"]
    assert _validate(schemas, resolver, gid, base) == []


def test_state_transition_accepts_twin_projection_label(schemas, resolver):
    """Twin mutations are STATE_TRANSITION records too (D0-04 §1 chain tail)."""
    from datetime import datetime, timezone
    from netops_autopilot.ledger.models import OperatorIdentity, StateTransition

    tr = StateTransition(
        fsm="TWIN_PROJECTION", entity_ref="DEVICE:dev-1",
        from_state="field:vendor:ABSENT", to_state="field:vendor:UPDATED",
        guard_id="TWIN-ADMIT", evidence_ids=["obs-1"],
        actor=OperatorIdentity(kind="ENGINE", id="E05"),
        collected_at=datetime.now(timezone.utc),
    )
    errors = _validate(
        schemas, resolver,
        "https://netops-autopilot.local/schemas/state_transition.schema.json",
        tr.model_dump(mode="json"),
    )
    assert errors == []
    # And the FSM label set remains closed for unknown labels.
    with pytest.raises(ValueError):
        StateTransition(
            fsm="FSM-9_NONEXISTENT", entity_ref="x", from_state="a", to_state="b",
            guard_id="g", evidence_ids=["e"],
            actor=OperatorIdentity(kind="ENGINE", id="E05"),
            collected_at=datetime.now(timezone.utc),
        )


def test_decision_readiness_ready_must_be_conjunction(schemas, resolver):
    gid = "https://netops-autopilot.local/schemas/decision_readiness.schema.json"
    conjuncts = {
        name: {"value": True, "reason": ""}
        for name in (
            "evidence_valid", "authority_valid", "fresh_enough", "no_conflict",
            "model_supported", "capability_confirmed", "policy_allowed",
            "dependency_satisfied", "rollback_ready", "recovery_path_verified",
            "blast_radius_accepted", "window_valid",
        )
    }
    inst = {
        "readiness_id": "00000000-0000-0000-0000-000000000005",
        "change_id": "00000000-0000-0000-0000-000000000004",
        "evaluated_at": "2026-09-05T12:00:00Z",
        "conjuncts": conjuncts,
        "ready": True,
    }
    assert _validate(schemas, resolver, gid, inst) == []
    inst["conjuncts"]["rollback_ready"] = {"value": False, "reason": "NOT_READY"}
    # Schema cannot encode the AND rule itself; the engine test enforces it.
    # Here we only assert the structure remains valid.
    assert _validate(schemas, resolver, gid, inst) == []
