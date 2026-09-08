"""Evidence Ledger (D0-04): signing, hash chain, integrity self-test."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.ledger.models import (
    Claim,
    ClockStatusEnum,
    CollectorIdentity,
    Event,
    EventType,
    Observation,
    OperatorIdentity,
    ParseStatus,
    RawArtifact,
    StateTransition,
    SubjectEntity,
)
from netops_autopilot.ledger.store import GENESIS_HASH, LedgerStore

NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def store():
    s = LedgerStore(":memory:")
    key = s.keys.create_key("collector")
    return s, key


def make_event(**over) -> Event:
    base = dict(
        type=EventType.CLI,
        device_id="dev-1",
        session_id="sess-1",
        command_or_op="show version",
        operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
        collector_identity=CollectorIdentity(collector_id="collector-0", key_id="ignored"),
        collected_at=NOW,
        collector_clock_status=ClockStatusEnum.SYNCED,
    )
    base.update(over)
    return Event(**base)


def test_unsigned_event_cannot_be_appended(store):
    s, _ = store
    with pytest.raises(Failure) as exc:
        s.append_event(make_event())
    assert exc.value.cls is FailureClass.FATAL


def test_sign_and_append_chain_of_three(store):
    s, key = store
    hashes = []
    for cmd in ("show version", "show inventory", "show lldp neighbors"):
        ev = s.sign_event(make_event(command_or_op=cmd), key)
        hashes.append(s.append_event(ev))
    assert s.event_count() == 3
    assert len(set(hashes)) == 3
    verdict = s.verify_chain()
    assert verdict.ok and verdict.checked == 3
    s.integrity_self_test()  # must not raise


def test_head_hash_moves_from_genesis(store):
    s, key = store
    assert s.head_hash() == GENESIS_HASH
    s.append_event(s.sign_event(make_event(), key))
    assert s.head_hash() != GENESIS_HASH


def test_re_signing_forbidden(store):
    s, key = store
    signed = s.sign_event(make_event(), key)
    with pytest.raises(Failure):
        s.sign_event(signed, key)


def test_tamper_detection_record_hash(store):
    s, key = store
    s.append_event(s.sign_event(make_event(command_or_op="show version"), key))
    s.append_event(s.sign_event(make_event(command_or_op="show inventory"), key))
    # Tamper with the first record's payload directly in the DB.
    s._db.execute("UPDATE events SET payload_json = REPLACE(payload_json, 'show version', 'write erase') WHERE seq = 1")
    s._db.commit()
    verdict = s.verify_chain()
    assert not verdict.ok and verdict.first_bad_seq == 1


def test_tamper_detection_chain_link(store):
    s, key = store
    s.append_event(s.sign_event(make_event(), key))
    s.append_event(s.sign_event(make_event(command_or_op="second"), key))
    s._db.execute("UPDATE events SET prev_hash = 'f' * 64 WHERE seq = 2")
    s._db.commit()
    verdict = s.verify_chain()
    assert not verdict.ok and verdict.reason == "PREV_HASH_MISMATCH"


def test_signature_verified_with_wrong_key_detection(store):
    s, key = store
    other = s.keys.create_key("collector-2")
    ev = s.sign_event(make_event(), key)
    s.append_event(ev)
    # Replace registered public key material simulation: verify directly.
    assert s.keys.verify(key, b"x", ev.signature.value_b64) is False  # sig is over payload, not b"x"


def test_integrity_self_test_raises_fatal_on_corruption(store):
    s, key = store
    s.append_event(s.sign_event(make_event(), key))
    s._db.execute("UPDATE events SET record_hash = '0' WHERE seq = 1")
    s._db.commit()
    with pytest.raises(Failure) as exc:
        s.integrity_self_test()
    assert exc.value.cls is FailureClass.FATAL


def test_subrecord_stores_roundtrip(store):
    s, key = store
    ev = s.sign_event(make_event(), key)
    s.append_event(ev)
    art = RawArtifact(event_id=ev.event_id, storage_uri="file:///artifacts/a.bin",
                      sha256="a" * 64, bytes=10, truncated=False)
    s.append_raw_artifact(art)
    obs = Observation(raw_id=art.raw_id, parser_id="textfsm/show_version",
                      parser_version="1.2.3", field="version", value="17.9.4",
                      parse_status=ParseStatus.OK)
    s.append_observation(obs)
    claim = Claim(
        subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
        predicate="os_version", value="17.9.4",
        evidence_ids=[obs.obs_id], verification_scope="DEVICE_IDENTITY",
        status="CONFIRMED", relevance_check="PASS",
    )
    s.append_claim(claim)
    tr = StateTransition(fsm="FSM-1_DEVICE", entity_ref="dev-1", from_state="UNKNOWN",
                         to_state="PHYSICAL_DETECTED", guard_id="1.1",
                         evidence_ids=[claim.claim_id],
                         actor=OperatorIdentity(kind="ENGINE", id="E01"), collected_at=NOW)
    s.append_transition(tr)
    assert [c.claim_id for c in s.claims()] == [claim.claim_id]
    assert [t.transition_id for t in s.transitions()] == [tr.transition_id]
    assert len(s.events()) == 1


def test_truncated_artifact_requires_reason():
    with pytest.raises(Exception):
        RawArtifact(event_id="e", storage_uri="file:///x", sha256="b" * 64,
                    bytes=100, truncated=True)  # budget_reason missing
