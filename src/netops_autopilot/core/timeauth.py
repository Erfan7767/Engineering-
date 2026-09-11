"""Time Authority (D0-04 §4, ADR-0010).

* ``collected_at`` is ALWAYS the collector clock; device clocks are separate,
  untrusted fields.
* Freshness is evaluated AT DECISION TIME against the decision-class bound;
  the evaluated age is recorded on the decision record.
* With an UNSYNCED collector clock, age is a lower bound; decisions needing
  hard freshness return BLOCKED rather than a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from .failures import FailureClass


class ClockStatus(str, Enum):
    SYNCED = "SYNCED"
    UNSYNCED = "UNSYNCED"
    DRIFT_SUSPECTED = "DRIFT_SUSPECTED"


#: Freshness bounds in seconds per decision class (master spec §8).
DECISION_FRESHNESS_BOUNDS: dict[str, Optional[float]] = {
    "DEPLOY": 60.0,
    "ROLLBACK": 60.0,
    "DESIGN": 24 * 3600.0,
    "DOCUMENTATION": None,  # unbounded; age must be printed instead
    "MONITORING": 5 * 60.0,
}


def _require_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("naive datetime rejected: Time Authority requires aware timestamps")
    return dt


@dataclass(frozen=True)
class FreshnessVerdict:
    """Result of a freshness evaluation, persisted verbatim on decisions."""

    ok: bool
    age_seconds: float
    bound_seconds: Optional[float]
    clock_status: ClockStatus
    reason: str
    failure_class: Optional[FailureClass] = None


class TimeAuthority:
    """Collector-clock source + freshness evaluator.

    The clock callable is injectable for deterministic tests; production
    wiring uses the OS clock and records sync state from the platform's own
    time status.
    """

    def __init__(self, clock: Callable[[], datetime], status: ClockStatus = ClockStatus.SYNCED) -> None:
        self._clock = clock
        self.status = status

    def now(self) -> datetime:
        return _require_aware(self._clock())

    def age_seconds(self, collected_at: datetime) -> float:
        collected_at = _require_aware(collected_at)
        age = (self.now() - collected_at).total_seconds()
        if age < 0:
            # Collector clock went backwards; age is unknown — never negative.
            raise ValueError("collected_at in the future: clock anomaly, age undefined")
        return age

    def evaluate(self, decision_kind: str, collected_at: datetime, hard_freshness_required: bool = True) -> FreshnessVerdict:
        """Evaluate freshness of one evidence item for one decision class."""
        if decision_kind not in DECISION_FRESHNESS_BOUNDS:
            raise KeyError(f"unknown decision kind: {decision_kind!r}")
        bound = DECISION_FRESHNESS_BOUNDS[decision_kind]
        age = self.age_seconds(collected_at)

        if self.status is not ClockStatus.SYNCED and hard_freshness_required and bound is not None:
            return FreshnessVerdict(
                ok=False, age_seconds=age, bound_seconds=bound, clock_status=self.status,
                reason="COLLECTOR_CLOCK_NOT_SYNCED: age is only a lower bound",
                failure_class=FailureClass.BLOCKED,
            )
        if bound is None:
            return FreshnessVerdict(
                ok=True, age_seconds=age, bound_seconds=None, clock_status=self.status,
                reason="DOCUMENTATION_CLASS: unbounded, age must be printed",
            )
        if age <= bound:
            return FreshnessVerdict(
                ok=True, age_seconds=age, bound_seconds=bound, clock_status=self.status,
                reason="WITHIN_BOUND",
            )
        return FreshnessVerdict(
            ok=False, age_seconds=age, bound_seconds=bound, clock_status=self.status,
            reason="STALE: re-collect before proceeding or BLOCK",
            failure_class=None,  # caller decides re-collect vs BLOCKED
        )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FixedTimeAuthority(TimeAuthority):
    """Deterministic TimeAuthority for tests and replay.

    The clock is mutable so a test can advance time forward (e.g. simulate
    a long-running deploy). Awaits the aware-datetime invariant on every
    advance.
    """

    def __init__(self, start: Optional[datetime] = None) -> None:
        if start is None:
            start = datetime.now(timezone.utc)
        self._t = _require_aware(start)
        super().__init__(clock=lambda: self._t)

    def now(self) -> datetime:
        return self._t

    def advance(self, delta: timedelta) -> None:
        self._t = self._t + delta

    def iso(self) -> str:
        """ISO 8601 representation of the current clock value."""
        return self._t.isoformat()

