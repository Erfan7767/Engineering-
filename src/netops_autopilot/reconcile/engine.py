"""E22 Reconciliation Engine — baseline + typed drift (D2 scope of E22).

Responsibilities (D0-02 authority row "Drift remediation"):
* store immutable configuration baselines; the stored ``baseline_id`` is the
  exact evidence FSM-1 guard 1.8 requires for MODELED → MANAGED;
* diff an observed fact set against a baseline and emit TYPED drift records;
* classify every drift record — MANAGED (our own ledgered change),
  DEFAULT_RESTORED (value reverted to a documented platform default), or
  UNMANAGED_DRIFT (origin unknown ⇒ investigation, never silent acceptance);
* propose remediation as structured hint CODES only — this engine never
  emits device commands (that is E15's allowlisted boundary, L11).

No silent failure (L03): every difference produces a record; unknown facts
pass through as drift, never mangled or dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional

from ..core.counters import CounterCollector
from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from .defaults_db import PlatformDefaults


class DriftType(str, Enum):
    ADDED = "ADDED"        # in observed, not in baseline
    REMOVED = "REMOVED"    # in baseline, not in observed
    MODIFIED = "MODIFIED"  # in both, values differ


class DriftClassification(str, Enum):
    MANAGED = "MANAGED"                          # matches a ledgered change of ours
    DEFAULT_RESTORED = "DEFAULT_RESTORED"        # reverted to a known platform default
    UNMANAGED_DRIFT = "UNMANAGED_DRIFT"          # origin unknown ⇒ investigate


#: Remediation is proposed as codes; E15 owns any command materialization.
REMEDIATION_HINTS = {
    DriftClassification.MANAGED: "REVIEW_CHANGE_LEDGER",
    DriftClassification.DEFAULT_RESTORED: "REAPPLY_INTENT_OR_ACCEPT_DEFAULT",
    DriftClassification.UNMANAGED_DRIFT: "INVESTIGATE_ORIGIN",
}


@dataclass(frozen=True)
class BaselineRecord:
    baseline_id: str
    device_ref: str
    facts: Mapping[str, object]
    created_at: str  # injectable ISO-8601 (deterministic tests)


@dataclass(frozen=True)
class DriftRecord:
    key: str
    drift_type: DriftType
    baseline_value: object  # None when ADDED
    observed_value: object  # None when REMOVED
    classification: DriftClassification
    remediation_hint: str


@dataclass(frozen=True)
class ReconciliationReport:
    baseline_id: str
    device_ref: str
    records: tuple[DriftRecord, ...]

    @property
    def clean(self) -> bool:
        return not self.records

    def count(self, classification: DriftClassification) -> int:
        return sum(1 for r in self.records if r.classification is classification)


class BaselineStore:
    """Immutable baselines; a stored snapshot never changes after creation."""

    def __init__(self) -> None:
        self._baselines: dict[str, BaselineRecord] = {}

    def create(self, device_ref: str, facts: Mapping[str, object],
               created_at: Optional[str] = None) -> BaselineRecord:
        if not device_ref:
            raise Failure(cls=FailureClass.BLOCKED, causes=("BASELINE_DEVICE_REF_EMPTY",))
        if not facts:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("BASELINE_FACTS_EMPTY: a baseline of zero facts models nothing (L13)",))
        stamp = created_at if created_at is not None else datetime.now(timezone.utc).isoformat()
        record = BaselineRecord(baseline_id=new_id(), device_ref=device_ref,
                                facts=MappingProxyType(dict(facts)), created_at=stamp)
        self._baselines[record.baseline_id] = record
        return record

    def get(self, baseline_id: str) -> BaselineRecord:
        try:
            return self._baselines[baseline_id]
        except KeyError:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"BASELINE_UNKNOWN: {baseline_id} — no such baseline",)) from None

    def for_device(self, device_ref: str) -> tuple[BaselineRecord, ...]:
        return tuple(b for b in self._baselines.values() if b.device_ref == device_ref)


class ReconciliationEngine:
    """Deterministic baseline-vs-observed diffing with typed classification."""

    def __init__(self, store: BaselineStore,
                 defaults: Optional[PlatformDefaults] = None,
                 counters: Optional[CounterCollector] = None) -> None:
        self._store = store
        self._defaults = defaults
        self._counters = counters

    def evaluate(self, baseline_id: str, observed: Mapping[str, object], *,
                 managed_keys: frozenset[str] = frozenset(),
                 platform_key: Optional[str] = None) -> ReconciliationReport:
        baseline = self._store.get(baseline_id)
        records = self._diff(baseline, observed, managed_keys, platform_key)
        unmanaged = sum(1 for r in records if r.classification is DriftClassification.UNMANAGED_DRIFT)
        if unmanaged and self._counters is not None:
            self._counters.increment("unauthorized_changes",
                                     f"{baseline.device_ref}: {unmanaged} unmanaged drift record(s)")
        return ReconciliationReport(baseline_id=baseline.baseline_id,
                                    device_ref=baseline.device_ref, records=records)

    # ------------------------------------------------------------ internals
    def _diff(self, baseline: BaselineRecord, observed: Mapping[str, object],
              managed_keys: frozenset[str], platform_key: Optional[str]) -> tuple[DriftRecord, ...]:
        base, seen = dict(baseline.facts), dict(observed)
        records: list[DriftRecord] = []
        for key in sorted(set(base) | set(seen)):
            in_base, in_seen = key in base, key in seen
            if in_base and in_seen and base[key] == seen[key]:
                continue
            drift_type = (DriftType.ADDED if not in_base
                          else DriftType.REMOVED if not in_seen
                          else DriftType.MODIFIED)
            classification = self._classify(drift_type, key,
                                            base.get(key), seen.get(key),
                                            managed_keys, platform_key)
            records.append(DriftRecord(key=key, drift_type=drift_type,
                                       baseline_value=base.get(key),
                                       observed_value=seen.get(key),
                                       classification=classification,
                                       remediation_hint=REMEDIATION_HINTS[classification]))
        return tuple(records)

    def _classify(self, drift_type: DriftType, key: str, baseline_value: object,
                  observed_value: object, managed_keys: frozenset[str],
                  platform_key: Optional[str]) -> DriftClassification:
        # 1. A ledgered change of ours is expected drift, not a violation.
        if key in managed_keys:
            return DriftClassification.MANAGED
        # 2. Reversion to a KNOWN platform default is typed, not guessed.
        if self._defaults is not None and platform_key is not None:
            default = self._defaults.default_for(platform_key, key)
            if default is not None and not default.unknown:
                if drift_type is DriftType.MODIFIED and observed_value == default.value:
                    return DriftClassification.DEFAULT_RESTORED
                if drift_type is DriftType.REMOVED:
                    # Absence of the fact == platform default state.
                    return DriftClassification.DEFAULT_RESTORED
        # 3. Anything else: origin unknown ⇒ investigate (never silent, L03).
        return DriftClassification.UNMANAGED_DRIFT
