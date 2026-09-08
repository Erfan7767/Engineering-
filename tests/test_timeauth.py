"""Time Authority (D0-04 §4, ADR-0010)."""

from datetime import datetime, timedelta, timezone

import pytest

from netops_autopilot.core.timeauth import (
    ClockStatus,
    DECISION_FRESHNESS_BOUNDS,
    TimeAuthority,
)


T0 = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


def authority(status=ClockStatus.SYNCED, now=T0):
    return TimeAuthority(clock=lambda: now, status=status)


def test_bounds_match_spec_section_8():
    assert DECISION_FRESHNESS_BOUNDS["DEPLOY"] == 60.0
    assert DECISION_FRESHNESS_BOUNDS["ROLLBACK"] == 60.0
    assert DECISION_FRESHNESS_BOUNDS["DESIGN"] == 24 * 3600.0
    assert DECISION_FRESHNESS_BOUNDS["DOCUMENTATION"] is None


def test_fresh_evidence_passes_deploy_bound():
    ta = authority()
    v = ta.evaluate("DEPLOY", T0 - timedelta(seconds=30))
    assert v.ok and v.age_seconds == 30.0 and v.bound_seconds == 60.0


def test_stale_evidence_fails_deploy_bound():
    ta = authority()
    v = ta.evaluate("DEPLOY", T0 - timedelta(seconds=61))
    assert not v.ok
    assert v.reason.startswith("STALE")
    assert v.failure_class is None  # caller decides re-collect vs BLOCKED


def test_design_bound_is_24h():
    ta = authority()
    assert ta.evaluate("DESIGN", T0 - timedelta(hours=23)).ok
    assert not ta.evaluate("DESIGN", T0 - timedelta(hours=25)).ok


def test_documentation_unbounded_but_age_reported():
    ta = authority()
    v = ta.evaluate("DOCUMENTATION", T0 - timedelta(days=400))
    assert v.ok and v.bound_seconds is None
    assert v.age_seconds == pytest.approx(400 * 86400)
    assert "printed" in v.reason


def test_unsynced_clock_blocks_hard_freshness():
    ta = authority(status=ClockStatus.UNSYNCED)
    v = ta.evaluate("DEPLOY", T0 - timedelta(seconds=1), hard_freshness_required=True)
    assert not v.ok
    assert v.failure_class is not None
    assert v.failure_class.value == "BLOCKED"


def test_unsynced_clock_allowed_for_soft_decisions():
    ta = authority(status=ClockStatus.UNSYNCED)
    v = ta.evaluate("DOCUMENTATION", T0 - timedelta(seconds=1), hard_freshness_required=False)
    assert v.ok


def test_naive_datetime_rejected():
    ta = authority()
    with pytest.raises(ValueError):
        ta.age_seconds(datetime(2026, 9, 5, 12, 0, 0))


def test_future_timestamp_rejected():
    ta = authority()
    with pytest.raises(ValueError):
        ta.age_seconds(T0 + timedelta(seconds=1))
