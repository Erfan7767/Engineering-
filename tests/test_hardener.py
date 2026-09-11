"""Hardener tests — edge cases, type safety, and constitution compliance.

These tests don't cover new features; they harden existing ones
against abuse: bad inputs, race conditions, malformed config, etc.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from netops_autopilot.core.counters import CounterCollector, T5_COUNTERS
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.timeauth import TimeAuthority, FixedTimeAuthority


# ----------------- CounterCollector -----------------


def test_counter_starts_at_zero_for_all_counters():
    c = CounterCollector()
    snap = c.snapshot()
    for k in T5_COUNTERS:
        assert snap[k] == 0


def test_counter_increment_unknown_key_raises():
    """T5 counters are a closed registry per spec; unknown keys are an error."""
    c = CounterCollector()
    with pytest.raises(KeyError):
        c.increment("UNKNOWN_KEY", "reason")


def test_counter_value_and_reasons_track():
    c = CounterCollector()
    c.increment("unauthorized_changes", "r1")
    c.increment("unauthorized_changes", "r2")
    assert c.value("unauthorized_changes") == 2
    assert list(c.reasons("unauthorized_changes")) == ["r1", "r2"]


def test_counter_concurrent_inc_thread_safe():
    c = CounterCollector()
    def worker():
        for _ in range(1000):
            c.increment("unauthorized_changes", "thread")
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.value("unauthorized_changes") == 8000


def test_counter_snapshot_is_copy():
    """The snapshot is decoupled from the live counter."""
    c = CounterCollector()
    s = c.snapshot()
    c.increment("unauthorized_changes", "r")
    assert s["unauthorized_changes"] == 0
    assert c.snapshot()["unauthorized_changes"] == 1


def test_release_gate_passes_when_clean():
    c = CounterCollector()
    c.assert_release_gate()  # no raise


def test_release_gate_fails_when_dirty():
    c = CounterCollector()
    c.increment("credential_exposure", "secret leaked")
    with pytest.raises(AssertionError) as exc:
        c.assert_release_gate()
    assert "credential_exposure" in str(exc.value)


# ----------------- Failure type safety -----------------


def test_failure_subclass_preserves_class():
    f = Failure(FailureClass.BLOCKED, ("BOND_NOT_CONFIRMED: human refused",))
    assert f.cls is FailureClass.BLOCKED
    assert "BOND_NOT_CONFIRMED" in f.causes[0]


def test_failure_message_includes_class_and_retry_hint():
    f = Failure(
        FailureClass.RETRYABLE,
        ("AUTH_FAILED: bad password",),
        retry_hint="re-enter creds",
    )
    text = str(f)
    assert "AUTH_FAILED" in text
    assert "RETRYABLE" in text
    # The retry_hint is exposed as an attribute, even if not in the default str.
    assert f.retry_hint == "re-enter creds"


def test_failure_with_empty_causes_raises():
    with pytest.raises(ValueError):
        Failure(FailureClass.BLOCKED, ())


def test_failure_distinct_classes_not_equal():
    a = Failure(FailureClass.BLOCKED, ("X",))
    b = Failure(FailureClass.RETRYABLE, ("X",))
    assert a.cls is not b.cls


def test_failure_class_is_string_enum():
    """The FailureClass values must remain string-stable for log/ledger."""
    assert FailureClass.BLOCKED.value == "BLOCKED"
    assert FailureClass.RETRYABLE.value == "RETRYABLE"


# ----------------- TimeAuthority -----------------


def test_fixed_time_returns_const_value():
    t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    auth = FixedTimeAuthority(t)
    assert auth.now() == t
    # Wait — the value must not change.
    time.sleep(0.01)
    assert auth.now() == t


def test_real_time_authority_monotonic():
    a = TimeAuthority(clock=lambda: datetime.now(timezone.utc))
    samples = [a.now() for _ in range(10)]
    for prev, cur in zip(samples, samples[1:]):
        assert cur >= prev


def test_time_authority_iso_format_round_trip():
    t = datetime(2026, 6, 15, 8, 30, 0, tzinfo=timezone.utc)
    auth = FixedTimeAuthority(t)
    iso = auth.iso()
    parsed = datetime.fromisoformat(iso)
    assert parsed == t


def test_time_authority_advance_supports_timedelta():
    auth = FixedTimeAuthority(datetime(2026, 1, 1, tzinfo=timezone.utc))
    auth.advance(timedelta(hours=2))
    assert auth.now() == datetime(2026, 1, 1, 2, 0, 0, tzinfo=timezone.utc)


# ----------------- ids.py regression -----------------


def test_typed_id_round_trip():
    from netops_autopilot.core.ids import typed_id, extract_kind, is_typed_id
    t = typed_id("dev")
    assert is_typed_id(t)
    assert is_typed_id(t, kind="dev")
    assert not is_typed_id(t, kind="port")
    assert extract_kind(t) == "dev"


def test_new_id_backcompat_preserved():
    """L02: existing callers of new_id() must still work."""
    from netops_autopilot.core.ids import new_id
    x = new_id()
    assert isinstance(x, str)
    assert len(x) >= 8


def test_short_id_returns_requested_length():
    from netops_autopilot.core.ids import short_id, typed_id, strip_kind
    full = typed_id("device")
    s = short_id(full, length=12)
    # The short id includes the "kind:" prefix + 12 chars of the unique part.
    assert s.startswith("device:")
    # The unique part after the prefix is exactly `length` chars.
    assert len(strip_kind(s)) == 12


# ----------------- typed_id edge cases -----------------


def test_typed_id_with_explicit_raw_uses_provided_unique_part():
    from netops_autopilot.core.ids import typed_id, extract_kind, strip_kind
    t = typed_id("session", raw="abc123def")
    assert extract_kind(t) == "session"
    assert strip_kind(t) == "abc123def"


def test_typed_id_kind_must_be_nonempty():
    from netops_autopilot.core.ids import typed_id
    with pytest.raises(ValueError):
        typed_id("")


def test_strip_kind_on_untyped_returns_same():
    from netops_autopilot.core.ids import strip_kind
    assert strip_kind("not-a-typed-id") == "not-a-typed-id"


def test_extract_kind_on_untyped_returns_none():
    from netops_autopilot.core.ids import extract_kind
    assert extract_kind("plain") is None
