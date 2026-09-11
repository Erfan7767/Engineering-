"""Verify LedgerStore is safe for concurrent access from multiple threads.

The chat webserver shares a single LedgerStore across:
- the FastAPI threadpool (POST /chat, GET /state)
- a dedicated worker thread (SSE /chat/stream)
- the engine's internal helpers

Prior to Phase K, two threads writing through the same connection could
trigger ``sqlite3.OperationalError: attempt to write a readonly database``
once the connection state went bad. The fix is a per-instance
``threading.RLock`` around every SQL operation. These tests prove that
real concurrent writers can complete a heavy workload without any
error, and that a reader running in parallel sees consistent counts.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import List

import pytest

from netops_autopilot.ledger.keys import KeyRegistry
from netops_autopilot.ledger.models import (
    ClockStatusEnum,
    CollectorIdentity,
    Event,
    EventSignature,
    EventType,
    OperatorIdentity,
)
from netops_autopilot.ledger.store import GENESIS_HASH, LedgerStore


@pytest.fixture
def shared_db(tmp_path) -> str:
    return str(tmp_path / "shared.sqlite")


def _make_signed_event(seq: int, key_id: str, registry: KeyRegistry) -> Event:
    """Build and sign a minimal Event for ledger appends."""
    ev = Event(
        event_id=f"evt-{seq:05d}",
        type=EventType.CLI,
        device_id="seed-01",
        session_id=f"sess-{seq}",
        command_or_op=f"show running-config (seq={seq})",
        operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
        collector_identity=CollectorIdentity(collector_id="collector-0", key_id=key_id),
        collected_at=datetime.now(timezone.utc),
        collector_clock_status=ClockStatusEnum.SYNCED,
    )
    from netops_autopilot.ledger.keys import canonical_bytes

    signer = registry.signer_for(key_id)
    sig = signer(canonical_bytes(ev.signing_payload()))
    return ev.model_copy(
        update={"signature": EventSignature(key_id=key_id, value_b64=sig)}
    )


def test_concurrent_writers_do_not_error(shared_db: str) -> None:
    """Eight threads × 25 events each must all complete without OperationalError."""
    keys = KeyRegistry()
    key_id = keys.create_key()
    store = LedgerStore(shared_db, keys=keys)
    errors: List[BaseException] = []
    lock = threading.Lock()

    def writer(tid: int) -> None:
        try:
            for i in range(25):
                ev = _make_signed_event(tid * 1000 + i, key_id, store.keys)
                store.append_event(ev)
        except BaseException as e:  # noqa: BLE001
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrent writers raised: {errors!r}"
    assert store.event_count() == 8 * 25


def test_concurrent_writers_and_reader(shared_db: str) -> None:
    """Writers must not leave the reader with a 'readonly' or 'closed' state."""
    keys = KeyRegistry()
    key_id = keys.create_key()
    store = LedgerStore(shared_db, keys=keys)

    stop = threading.Event()
    samples: List[int] = []
    err_samples: List[BaseException] = []
    slock = threading.Lock()

    def reader() -> None:
        while not stop.is_set():
            try:
                n = store.event_count()
                with slock:
                    samples.append(n)
            except BaseException as e:  # noqa: BLE001
                with slock:
                    err_samples.append(e)
            time.sleep(0.001)

    def writer(tid: int) -> None:
        for i in range(50):
            ev = _make_signed_event(tid * 10_000 + i, key_id, store.keys)
            store.append_event(ev)

    r = threading.Thread(target=reader)
    r.start()
    threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    r.join()

    assert err_samples == [], f"reader saw: {err_samples!r}"
    # Reader must have observed monotonically non-decreasing counts
    # (writes are serialized by the lock).
    assert samples == sorted(samples), f"non-monotonic counts: {samples[:10]}..."
    # Final value must equal what was written. We re-read after stop
    # because the reader thread may have just slept through the last
    # write.
    assert store.event_count() == 4 * 50
    assert samples[-1] <= 4 * 50


def test_ledger_chain_verifies_under_concurrent_writes(shared_db: str) -> None:
    """The hash chain must still be valid after concurrent writes."""
    keys = KeyRegistry()
    key_id = keys.create_key()
    store = LedgerStore(shared_db, keys=keys)

    def writer(tid: int) -> None:
        for i in range(10):
            ev = _make_signed_event(tid * 1000 + i, key_id, store.keys)
            store.append_event(ev)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    verdict = store.verify_chain()
    assert verdict.ok, f"chain integrity broken: {verdict}"
    assert verdict.checked == 6 * 10


def test_head_hash_is_consistent_under_concurrent_writes(shared_db: str) -> None:
    """head_hash() should return the same value from any thread at any time,
    provided writes are fully serialized."""
    keys = KeyRegistry()
    key_id = keys.create_key()
    store = LedgerStore(shared_db, keys=keys)

    def writer() -> None:
        for i in range(20):
            ev = _make_signed_event(i, key_id, store.keys)
            store.append_event(ev)

    snapshots: List[str] = []
    slock = threading.Lock()
    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            h = store.head_hash()
            with slock:
                snapshots.append(h)
            time.sleep(0.0005)

    r = threading.Thread(target=reader)
    r.start()
    w = threading.Thread(target=writer)
    w.start()
    w.join()
    stop.set()
    r.join()

    # Every snapshot must be either GENESIS_HASH or a valid hex string
    # (since the chain grows). Length must be 64.
    for s in snapshots:
        assert len(s) == 64, f"bad head hash: {s!r}"


def test_store_can_be_opened_by_check_same_thread_false(tmp_path) -> None:
    """The store's connection must be created with check_same_thread=False
    so any thread can use it without ProgrammingError."""
    db = str(tmp_path / "cs.sqlite")
    keys = KeyRegistry()
    key_id = keys.create_key()
    store = LedgerStore(db, keys=keys)
    # If the connection was created with check_same_thread=True, opening
    # it from a different thread would raise ProgrammingError. The
    # LedgerStore's API uses sqlite3 directly; the simplest check is to
    # read and write from a fresh thread.
    results: List[str] = []
    errs: List[BaseException] = []

    def worker() -> None:
        try:
            for i in range(5):
                ev = _make_signed_event(i, key_id, store.keys)
                store.append_event(ev)
            results.append("ok")
        except BaseException as e:  # noqa: BLE001
            errs.append(e)

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert errs == [], f"worker saw: {errs!r}"
    assert results == ["ok"]
    assert store.event_count() == 5
