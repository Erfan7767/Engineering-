"""D4 Agent Boundary Guard: schema, entity guard, raw commands, secrets."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.agents.context import SECRET_PREDICATES, AgentContext, build_context
from netops_autopilot.agents.guard import AgentGuard
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.ledger.models import Claim, SubjectEntity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.twin import DigitalTwin

NOW = datetime(2026, 9, 8, 8, 0, 0, tzinfo=timezone.utc)


def claim(predicate, value, etype="DEVICE", ref="dev-1"):
    return Claim(subject_entity=SubjectEntity(entity_type=etype, entity_ref=ref),
                 predicate=predicate, value=value, evidence_ids=["obs-1"],
                 verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                 relevance_check="PASS")


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    twin = DigitalTwin(LedgerStore(":memory:"), CounterCollector())
    twin.apply_claim(claim("vendor", "mikrotik"), NOW)
    twin.apply_claim(claim("os", "routeros"), NOW)
    twin.apply_claim(claim("password_hash", "$6$rounds=5000$salt$hash"), NOW)
    twin.apply_claim(claim("name", "edge-1", etype="INTERFACE", ref="ether1"), NOW)
    return AgentGuard(twin, counters), counters, twin


def valid_payload(**over):
    payload = {
        "agent": "A3_ARCHITECT",
        "intent": {"kind": "DESIGN", "summary": "isolate guest VLAN"},
        "target_entities": [{"entity_type": "DEVICE", "entity_ref": "dev-1"}],
        "required_capabilities": [{"domain": "switching", "feature": "vlan",
                                   "operations": ["configure", "validate"]}],
        "proposed_change": {"description": "create guest VLAN and isolation policy"},
        "expected_state": {"guest_vlan": 999},
        "risk_hypothesis": {"blast_radius_guess": "single switch", "worst_case": "guest loss of internet"},
        "evidence_requirements": [{"verification_scope": "CONFIGURATION", "purpose": "baseline"}],
        "rationale": "sponsor requirement R-7",
    }
    payload.update(over)
    return payload


# ------------------------------------------------------------------- schema
def test_valid_intent_object_is_accepted(rig):
    guard, counters, _ = rig
    verdict = guard.admit(valid_payload())
    assert verdict.accepted and verdict.quarantine_reasons == ()
    assert counters.value("entity_hallucinations") == 0


def test_schema_invalid_payload_is_quarantined(rig):
    guard, _, _ = rig
    bad = valid_payload(intent={"kind": "NOT_A_KIND", "summary": "x"})
    verdict = guard.admit(bad)
    assert verdict.quarantined
    assert any(r.startswith("SCHEMA_INVALID") for r in verdict.quarantine_reasons)


def test_extra_top_level_fields_are_rejected(rig):
    guard, _, _ = rig
    verdict = guard.admit(valid_payload(smuggled_field="x"))
    assert verdict.quarantined


def test_raw_command_string_in_proposed_change_is_quarantined(rig):
    """Prefixes come FROM the vendor allowlists — data-driven, not hardcoded."""
    guard, _, _ = rig
    for command in ("show version", "show running-config", "/interface/print detail",
                    "/system/resource/print", "get system status"):
        payload = valid_payload(proposed_change={"steps": command})
        verdict = guard.admit(payload)
        if any(r.startswith("RAW_COMMAND_DETECTED") for r in verdict.quarantine_reasons):
            continue
        pytest.fail(f"raw command not quarantined: {command!r} → {verdict.quarantine_reasons}")


def test_descriptive_text_is_not_false_quarantined(rig):
    guard, _, _ = rig
    payload = valid_payload(proposed_change={"description": "create the guest isolation policy on VLAN 999"})
    assert guard.admit(payload).accepted


# -------------------------------------------------------------- entity guard
def test_hallucinated_entities_are_counted_and_quarantined(rig):
    guard, counters, _ = rig
    payload = valid_payload(target_entities=[
        {"entity_type": "DEVICE", "entity_ref": "dev-1"},
        {"entity_type": "DEVICE", "entity_ref": "ghost-switch"},
        {"entity_type": "INTERFACE", "entity_ref": "ether42"},
    ])
    verdict = guard.admit(payload)
    assert verdict.quarantined
    assert verdict.entity_violations == ("DEVICE:ghost-switch", "INTERFACE:ether42")
    assert counters.value("entity_hallucinations") == 1  # one admission event
    assert "ghost-switch" in list(counters.reasons("entity_hallucinations"))[0]


def test_existing_entities_pass(rig):
    guard, counters, _ = rig
    payload = valid_payload(target_entities=[
        {"entity_type": "DEVICE", "entity_ref": "dev-1"},
        {"entity_type": "INTERFACE", "entity_ref": "ether1"},
    ])
    assert guard.admit(payload).accepted
    assert counters.value("entity_hallucinations") == 0


# ------------------------------------------------------------------ secrets
def test_credential_patterns_are_quarantined_and_counted(rig):
    guard, counters, _ = rig
    payload = valid_payload(rationale="set password: hunter2 for admin")
    verdict = guard.admit(payload)
    assert "CREDENTIAL_PATTERN_DETECTED" in verdict.quarantine_reasons
    assert counters.value("credential_exposure") == 1


def test_private_key_material_is_quarantined(rig):
    guard, counters, _ = rig
    payload = valid_payload(rationale="use key -----BEGIN RSA PRIVATE KEY----- material")
    assert "CREDENTIAL_PATTERN_DETECTED" in guard.admit(payload).quarantine_reasons


def test_all_checks_report_together(rig):
    """Every reason surfaces in one verdict — no drip-feeding, no silence."""
    guard, counters, _ = rig
    payload = valid_payload(
        intent={"kind": "BOGUS", "summary": "x"},
        target_entities=[{"entity_type": "DEVICE", "entity_ref": "ghost"}],
        proposed_change={"steps": "show version"},
        rationale="password: leaked",
    )
    verdict = guard.admit(payload)
    kinds = {r.split(":")[0] for r in verdict.quarantine_reasons}
    assert kinds == {"SCHEMA_INVALID", "ENTITY_NOT_IN_INVENTORY",
                     "RAW_COMMAND_DETECTED", "CREDENTIAL_PATTERN_DETECTED"}


def test_verdict_is_deterministic(rig):
    guard, _, _ = rig
    payload = valid_payload(target_entities=[{"entity_type": "DEVICE", "entity_ref": "ghost"}])
    assert guard.admit(payload) == guard.admit(payload)


# ---------------------------------------------------------- context builder
def test_context_redacts_secret_predicates(rig):
    _, _, twin = rig
    ctx = build_context(twin, (("DEVICE", "dev-1"), ("INTERFACE", "ether1")))
    assert isinstance(ctx, AgentContext)
    assert ctx.has_secret_leak() is False
    predicates = {(f.entity_ref, f.predicate) for f in ctx.facts}
    assert ("dev-1", "vendor") in predicates and ("ether1", "name") in predicates
    assert not any(p == "password_hash" for _, p in predicates)
    redacted = {(r.entity_ref, r.predicate) for r in ctx.redactions}
    assert ("dev-1", "password_hash") in redacted


def test_context_never_invents_absent_entities(rig):
    _, _, twin = rig
    ctx = build_context(twin, (("DEVICE", "no-such"),))
    assert ctx.facts == () and ctx.redactions == ()


def test_context_is_deterministic_and_sorted(rig):
    _, _, twin = rig
    refs = (("INTERFACE", "ether1"), ("DEVICE", "dev-1"), ("DEVICE", "dev-1"))
    a = build_context(twin, refs)
    b = build_context(twin, refs)
    assert a == b
    keys = [(f.entity_type, f.entity_ref, f.predicate) for f in a.facts]
    assert keys == sorted(keys)


def test_secret_predicate_list_is_frozen():
    with pytest.raises(AttributeError):
        SECRET_PREDICATES.add("new_secret")  # type: ignore[attr-defined]
