"""LedgerStore — SQLite append-only, hash-chained, signature-verifying.

Implements D0-04: EVENT chain with hash chaining + Ed25519 signatures,
RAW_ARTIFACT/OBSERVATION/CLAIM/STATE_TRANSITION stores, and the startup
integrity self-test (L03: mismatch ⇒ FATAL).

This is the ONLY write path to ledger persistence (D0-06 rule); no engine
may open the database directly.

Thread safety: every write/read is serialized by a per-instance
``threading.RLock``. The same LedgerStore may safely be shared by
multiple threads (FastAPI threadpool, SSE worker, /state pollers).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional

from ..core.failures import Failure, FailureClass
from .keys import KeyRegistry, canonical_bytes
from .models import Claim, Event, Observation, RawArtifact, StateTransition

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    device_id TEXT,
    payload_json TEXT NOT NULL,
    signature_json TEXT,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_artifacts (
    raw_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    obs_id TEXT PRIMARY KEY,
    raw_id TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (
    claim_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transitions (
    transition_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);
"""


def _record_hash(prev_hash: str, payload: dict, signature_json: Optional[str]) -> str:
    envelope = {"prev_hash": prev_hash, "payload": payload, "signature": json.loads(signature_json) if signature_json else None}
    return hashlib.sha256(canonical_bytes(envelope)).hexdigest()


@dataclass(frozen=True)
class ChainVerdict:
    ok: bool
    checked: int
    first_bad_seq: Optional[int] = None
    reason: str = ""


class LedgerStore:
    """SQLite-backed evidence ledger."""

    def __init__(self, db_path: str = ":memory:", keys: Optional[KeyRegistry] = None) -> None:
        # check_same_thread=False so a single LedgerStore may be used
        # from any thread. The per-instance ``_lock`` (RLock) is the
        # actual serializer; SQLite connections themselves are not
        # safe for concurrent use even with that flag.
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self.keys = keys or KeyRegistry()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ chain
    def head_hash(self) -> str:
        with self._lock:
            row = self._db.execute("SELECT record_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            return row[0] if row else GENESIS_HASH

    def append_event(self, event: Event) -> str:
        """Sign (if unsigned), chain, and persist one Event. Returns record hash."""
        if event.signature is None:
            raise Failure(
                cls=FailureClass.FATAL,
                causes=("UNSIGNED_EVENT: events must be signed before append (use sign_event)"),
            )
        payload = event.signing_payload()
        signature_json = event.signature.model_dump_json()
        with self._lock:
            prev = self.head_hash()
            record_hash = _record_hash(prev, payload, signature_json)
            try:
                self._db.execute(
                    "INSERT INTO events (event_id, type, device_id, payload_json, signature_json, prev_hash, record_hash) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (event.event_id, event.type.value, event.device_id,
                     json.dumps(payload, sort_keys=True), signature_json, prev, record_hash),
                )
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                raise Failure(cls=FailureClass.FATAL, causes=(f"LEDGER_WRITE_REJECTED: {exc}",)) from exc
        return record_hash

    def sign_event(self, event: Event, key_id: str) -> Event:
        """Attach an Ed25519 signature over the canonical signing payload."""
        from .models import EventSignature

        if event.signature is not None:
            raise Failure(cls=FailureClass.FATAL, causes=("EVENT_ALREADY_SIGNED: re-signing is forbidden",))
        signer = self.keys.signer_for(key_id)
        sig = signer(canonical_bytes(event.signing_payload()))
        return event.model_copy(update={"signature": EventSignature(key_id=key_id, value_b64=sig)})

    # ------------------------------------------------------------ sub-records
    def append_raw_artifact(self, artifact: RawArtifact) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO raw_artifacts (raw_id, event_id, payload_json) VALUES (?,?,?)",
                (artifact.raw_id, artifact.event_id, artifact.model_dump_json()),
            )
            self._db.commit()

    def append_observation(self, obs: Observation) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO observations (obs_id, raw_id, payload_json) VALUES (?,?,?)",
                (obs.obs_id, obs.raw_id, obs.model_dump_json()),
            )
            self._db.commit()

    def append_claim(self, claim: Claim) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO claims (claim_id, payload_json) VALUES (?,?)",
                (claim.claim_id, claim.model_dump_json()),
            )
            self._db.commit()

    def append_transition(self, tr: StateTransition) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO transitions (transition_id, payload_json) VALUES (?,?)",
                (tr.transition_id, tr.model_dump_json()),
            )
            self._db.commit()

    # --------------------------------------------------------------- queries
    def event_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def events(self) -> list[Event]:
        with self._lock:
            rows = self._db.execute("SELECT payload_json, signature_json FROM events ORDER BY seq").fetchall()
        out: list[Event] = []
        for payload_json, signature_json in rows:
            data = json.loads(payload_json)
            data["signature"] = json.loads(signature_json)
            out.append(Event.model_validate(data))
        return out

    def claims(self) -> list[Claim]:
        with self._lock:
            rows = self._db.execute("SELECT payload_json FROM claims ORDER BY rowid").fetchall()
        return [Claim.model_validate_json(r[0]) for r in rows]

    def observations(self) -> list[Observation]:
        with self._lock:
            rows = self._db.execute("SELECT payload_json FROM observations ORDER BY rowid").fetchall()
        return [Observation.model_validate_json(r[0]) for r in rows]

    def raw_artifacts(self) -> list[RawArtifact]:
        with self._lock:
            rows = self._db.execute("SELECT payload_json FROM raw_artifacts ORDER BY rowid").fetchall()
        return [RawArtifact.model_validate_json(r[0]) for r in rows]

    def transitions(self) -> list[StateTransition]:
        with self._lock:
            rows = self._db.execute("SELECT payload_json FROM transitions ORDER BY rowid").fetchall()
        return [StateTransition.model_validate_json(r[0]) for r in rows]

    # -------------------------------------------------------------- integrity
    def verify_chain(self) -> ChainVerdict:
        """Recompute every hash and verify every signature. FATAL on failure."""
        with self._lock:
            prev = GENESIS_HASH
            rows = self._db.execute(
                "SELECT seq, payload_json, signature_json, prev_hash, record_hash FROM events ORDER BY seq"
            ).fetchall()
        for seq, payload_json, signature_json, stored_prev, stored_hash in rows:
            payload = json.loads(payload_json)
            if stored_prev != prev:
                return ChainVerdict(ok=False, checked=seq, first_bad_seq=seq, reason="PREV_HASH_MISMATCH")
            if _record_hash(stored_prev, payload, signature_json) != stored_hash:
                return ChainVerdict(ok=False, checked=seq, first_bad_seq=seq, reason="RECORD_HASH_MISMATCH")
            sig = json.loads(signature_json)
            if sig is None or not self.keys.verify(sig["key_id"], canonical_bytes(payload), sig["value_b64"]):
                return ChainVerdict(ok=False, checked=seq, first_bad_seq=seq, reason="SIGNATURE_INVALID")
            prev = stored_hash
        return ChainVerdict(ok=True, checked=len(rows))

    def integrity_self_test(self) -> None:
        """Startup self-test (D0-04 §3): mismatch ⇒ FATAL."""
        verdict = self.verify_chain()
        if not verdict.ok:
            raise Failure(
                cls=FailureClass.FATAL,
                causes=(f"LEDGER_INTEGRITY_{verdict.reason}: seq={verdict.first_bad_seq}",),
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()
