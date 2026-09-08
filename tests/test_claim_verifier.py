"""Claim/Relevance Verifier: D0-04 §5 three rules, fail-closed, full report."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.ledger.claim_verifier import ClaimVerifier
from netops_autopilot.ledger.models import (
    Claim, ClockStatusEnum, CollectorIdentity, Event, EventType,
    OperatorIdentity, RawArtifact, SubjectEntity,
)
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.parsers.catalog import default_registry

NOW = datetime(2026, 9, 8, 9, 0, 0, tzinfo=timezone.utc)
RAW_TEXT = b"uptime: 1d2h\nversion: 7.14\nbuild-time: 2026-01-01\ncpu: arm\nboard-name: hAP ax3\n"
COMMAND = "/system/resource/print"


def make_event(store, key, device_id="dev-1", command_or_op=COMMAND) -> str:
    ev = Event(type=EventType.CLI, device_id=device_id, session_id="sess-1",
               command_or_op=command_or_op,
               operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
               collector_identity=CollectorIdentity(collector_id="collector-0", key_id="ignored"),
               collected_at=NOW, collector_clock_status=ClockStatusEnum.SYNCED)
    store.append_event(store.sign_event(ev, key))
    return ev.event_id  # append_event returns the CHAIN HASH, not the id


def make_artifact(store, event_id) -> str:
    artifact = RawArtifact(event_id=event_id, storage_uri="mem://raw-1",
                           sha256="ab" * 32, bytes=len(RAW_TEXT), truncated=False)
    store.append_raw_artifact(artifact)
    return artifact.raw_id


PARSER_ID = "keyvalue/routeros_system_resource_print"


@pytest.fixture()
def ledger():
    """Store with one dev-1 '/system/resource/print' evidence chain parsed
    by the golden RouterOS parser."""
    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    registry = default_registry()
    parser = registry.get(PARSER_ID, "1.0.0")
    event_id = make_event(store, key)
    raw_id = make_artifact(store, event_id)
    for obs in parser.parse(RAW_TEXT, raw_id):
        store.append_observation(obs)
    return store, registry


def obs_of(store, field: str):
    matches = [o for o in store.observations() if o.field == field]
    assert len(matches) == 1
    return matches[0]


def claim(predicate, evidence_ids, entity_type="DEVICE", entity_ref="dev-1"):
    return Claim(subject_entity=SubjectEntity(entity_type=entity_type, entity_ref=entity_ref),
                 predicate=predicate, value="7.14", evidence_ids=list(evidence_ids),
                 verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                 relevance_check="PASS")


# ------------------------------------------------------------------ rule set
def test_relevant_claim_is_admitted(ledger):
    store, registry = ledger
    verdict = ClaimVerifier(store, registry).verify(claim("version", [obs_of(store, "version").obs_id]))
    assert verdict.admitted and verdict.relevance_check == "PASS"
    assert verdict.reasons == ()


def test_unknown_evidence_is_rejected(ledger):
    store, registry = ledger
    verdict = ClaimVerifier(store, registry).verify(claim("version", ["ghost-obs-id"]))
    assert not verdict.admitted
    assert verdict.reasons == ("EVIDENCE_UNKNOWN:ghost-obs-id",)


def test_superseded_observation_carries_no_relevance(ledger):
    """The verifier reads persisted state: a superseded observation (re-parse
    produced a newer one, D0-04 §1) carries no relevance."""
    store, registry = ledger
    from netops_autopilot.ledger.models import Observation, ParseStatus
    sup = Observation(raw_id=store.raw_artifacts()[0].raw_id, parser_id=PARSER_ID,
                      parser_version="1.0.0", field="old_version", value="7.13",
                      parse_status=ParseStatus.OK, superseded_by="newer-obs")
    store.append_observation(sup)
    verdict = ClaimVerifier(store, registry).verify(claim("old_version", [sup.obs_id]))
    assert "EVIDENCE_SUPERSEDED:" + sup.obs_id in verdict.reasons


def test_unparsed_field_proves_nothing(ledger):
    """A MISSING observation proves nothing about a value (L01)."""
    store, registry = ledger
    from netops_autopilot.ledger.models import Observation, ParseStatus
    missing_obs = Observation(raw_id=store.raw_artifacts()[0].raw_id, parser_id=PARSER_ID,
                              parser_version="1.0.0", field="ghost_field", value=None,
                              parse_status=ParseStatus.MISSING)
    store.append_observation(missing_obs)
    verdict = ClaimVerifier(store, registry).verify(claim("ghost_field", [missing_obs.obs_id]))
    assert any(r.startswith("EVIDENCE_NOT_PARSED") for r in verdict.reasons)


def test_evidence_of_another_field_is_rejected(ledger):
    store, registry = ledger
    verdict = ClaimVerifier(store, registry).verify(claim("cpu", [obs_of(store, "version").obs_id]))
    assert any(r.startswith("EVIDENCE_FIELD_MISMATCH") for r in verdict.reasons)


def test_command_registry_mismatch_is_rejected(ledger):
    """Evidence produced by a different command than the parser's registry
    entry breaks rule 2 — even if the field parsed fine."""
    store, registry = ledger
    key = store.keys.create_key("collector2")
    event_id = make_event(store, key, command_or_op="/something/else")
    raw_id = make_artifact(store, event_id)
    parser = registry.get(PARSER_ID, "1.0.0")
    for obs in parser.parse(RAW_TEXT, raw_id):
        store.append_observation(obs)
    bad_obs = [o for o in store.observations() if o.raw_id == raw_id and o.field == "version"][0]
    verdict = ClaimVerifier(store, registry).verify(claim("version", [bad_obs.obs_id]))
    assert any(r.startswith("COMMAND_REGISTRY_MISMATCH") for r in verdict.reasons)


def test_device_mismatch_is_rejected(ledger):
    store, registry = ledger
    verdict = ClaimVerifier(store, registry).verify(
        claim("version", [obs_of(store, "version").obs_id], entity_ref="dev-2"))
    assert any(r.startswith("DEVICE_MISMATCH") for r in verdict.reasons)


def test_cross_device_evidence_for_non_device_subject_is_rejected(ledger):
    store, registry = ledger
    key = store.keys.create_key("collector3")
    event_id = make_event(store, key, device_id="dev-9")
    raw_id = make_artifact(store, event_id)
    parser = registry.get(PARSER_ID, "1.0.0")
    for obs in parser.parse(RAW_TEXT, raw_id):
        store.append_observation(obs)
    other = [o for o in store.observations() if o.raw_id == raw_id and o.field == "version"][0]
    first_raw = store.raw_artifacts()[0].raw_id
    first = [o for o in store.observations() if o.raw_id == first_raw and o.field == "version"][0]
    verdict = ClaimVerifier(store, registry).verify(
        claim("version", [first.obs_id, other.obs_id], entity_type="INTERFACE", entity_ref="ether1"))
    assert any(r.startswith("CROSS_DEVICE_EVIDENCE_UNDECLARED") for r in verdict.reasons)


def test_all_violations_report_together_and_deterministically(ledger):
    store, registry = ledger
    verifier = ClaimVerifier(store, registry)
    bad = claim("version", ["ghost", obs_of(store, "cpu").obs_id], entity_ref="dev-2")
    v1 = verifier.verify(bad)
    assert not v1.admitted
    kinds = {r.split(":")[0] for r in v1.reasons}
    assert kinds == {"EVIDENCE_UNKNOWN", "EVIDENCE_FIELD_MISMATCH"}
    assert verifier.verify(bad) == v1
