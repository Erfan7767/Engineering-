"""Failure semantics (D0-01 §3): single vocabulary, no silent failure."""

import pytest

from netops_autopilot.core.failures import Failure, FailureClass, blocked


def test_vocabulary_matches_spec_exactly():
    assert {c.value for c in FailureClass} == {
        "RETRYABLE", "BLOCKED", "ROLLED_BACK", "PARTIAL", "MANUAL_REQUIRED", "FATAL",
    }


def test_failure_requires_causes():
    with pytest.raises(ValueError):
        Failure(cls=FailureClass.BLOCKED, causes=())


def test_retry_hint_only_for_retryable():
    Failure(cls=FailureClass.RETRYABLE, causes=("TRANSIENT",), retry_hint="backoff 2s")
    with pytest.raises(ValueError):
        Failure(cls=FailureClass.BLOCKED, causes=("X",), retry_hint="nope")


def test_partial_requires_counts():
    Failure(cls=FailureClass.PARTIAL, causes=("APPLY_FAILED",), count=1, total=3)
    with pytest.raises(ValueError):
        Failure(cls=FailureClass.PARTIAL, causes=("APPLY_FAILED",), count=0, total=3)
    with pytest.raises(ValueError):
        Failure(cls=FailureClass.PARTIAL, causes=("APPLY_FAILED",), count=4, total=3)


def test_blocked_helper():
    f = blocked("PORT_NOT_IN_TWIN", "INTERFACE_EXISTENCE missing")
    assert f.cls is FailureClass.BLOCKED
    assert f.causes[0] == "PORT_NOT_IN_TWIN"


def test_failure_is_exception():
    """Engines surface failures as exceptions — no silent error path (L03)."""
    assert issubclass(Failure, Exception)
