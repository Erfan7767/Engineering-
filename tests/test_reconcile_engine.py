"""E22 Reconciliation Engine (D2 scope): baselines, typed drift, counters."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure
from netops_autopilot.reconcile.defaults_db import PlatformDefaults
from netops_autopilot.reconcile.engine import (
    BaselineStore,
    DriftClassification,
    DriftType,
    REMEDIATION_HINTS,
    ReconciliationEngine,
)

TS = "2026-09-07T09:00:00+00:00"

DEFAULTS = PlatformDefaults({"platforms": {"test/os": {
    "ntp_server": {"value": "10.0.0.1", "source": "documented"},
    "banner": {"value": "UNKNOWN", "source": "not_recorded"},
}}})


@pytest.fixture()
def store():
    s = BaselineStore()
    s.create("dev-1", {"ntp_server": "10.0.0.5", "syslog_host": "10.0.0.9", "ssh_enabled": True}, TS)
    return s


@pytest.fixture()
def counters():
    return CounterCollector()


def engine(store, counters, defaults=DEFAULTS):
    return ReconciliationEngine(store, defaults=defaults, counters=counters)


# ---------------------------------------------------------------- baselines
def test_baseline_round_trip_and_lookup(store):
    records = store.for_device("dev-1")
    assert len(records) == 1
    baseline = records[0]
    assert store.get(baseline.baseline_id) is baseline
    assert baseline.created_at == TS
    assert store.for_device("no-such-device") == ()


def test_baseline_stored_snapshot_is_immutable(store):
    baseline = store.for_device("dev-1")[0]
    assert baseline.facts == {"ntp_server": "10.0.0.5", "syslog_host": "10.0.0.9", "ssh_enabled": True}
    with pytest.raises(TypeError):
        baseline.facts["injected"] = "x"  # frozen dataclass mapping ref


def test_empty_facts_baseline_refused():
    s = BaselineStore()
    with pytest.raises(Failure) as exc:
        s.create("dev-1", {}, TS)
    assert "BASELINE_FACTS_EMPTY" in exc.value.causes[0]
    with pytest.raises(Failure):
        s.create("", {"a": 1}, TS)


def test_unknown_baseline_id_is_typed(store):
    with pytest.raises(Failure) as exc:
        store.get("no-such-id")
    assert "BASELINE_UNKNOWN" in exc.value.causes[0]


# -------------------------------------------------------------------- drift
def test_identical_observed_is_clean(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.0.0.5", "syslog_host": "10.0.0.9", "ssh_enabled": True})
    assert report.clean and report.records == ()
    assert counters.value("unauthorized_changes") == 0


def test_added_modified_removed_are_all_typed(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.9.9.9",           # MODIFIED (not default)
         "ssh_enabled": True,                 # unchanged
         "new_acl": "block-guests"})          # ADDED
    by_key = {r.key: r for r in report.records}
    assert set(by_key) == {"ntp_server", "syslog_host", "new_acl"}
    assert by_key["ntp_server"].drift_type is DriftType.MODIFIED
    assert by_key["syslog_host"].drift_type is DriftType.REMOVED
    assert by_key["syslog_host"].observed_value is None
    assert by_key["new_acl"].drift_type is DriftType.ADDED
    assert by_key["new_acl"].baseline_value is None
    # deterministic ordering by key
    assert [r.key for r in report.records] == sorted(r.key for r in report.records)


def test_records_are_sorted_deterministically(store, counters):
    eng = engine(store, counters)
    bid = store.for_device("dev-1")[0].baseline_id
    observed = {"ssh_enabled": False, "ntp_server": "10.9.9.9"}
    assert eng.evaluate(bid, observed).records == eng.evaluate(bid, observed).records


# ---------------------------------------------------------- classification
def test_managed_change_is_expected_drift(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.1.1.1", "syslog_host": "10.0.0.9", "ssh_enabled": True},
        managed_keys=frozenset({"ntp_server"}))
    assert report.records[0].classification is DriftClassification.MANAGED
    assert report.records[0].remediation_hint == "REVIEW_CHANGE_LEDGER"
    assert counters.value("unauthorized_changes") == 0  # our own ledgered change


def test_reversion_to_known_default_is_default_restored(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.0.0.1", "syslog_host": "10.0.0.9", "ssh_enabled": True},
        platform_key="test/os")
    record = report.records[0]
    assert record.classification is DriftClassification.DEFAULT_RESTORED
    assert record.remediation_hint == "REAPPLY_INTENT_OR_ACCEPT_DEFAULT"
    assert counters.value("unauthorized_changes") == 0  # typed, not unmanaged


def test_removal_of_fact_with_known_default_is_default_restored(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"syslog_host": "10.0.0.9", "ssh_enabled": True},  # ntp_server removed
        platform_key="test/os")
    by_key = {r.key: r for r in report.records}
    assert by_key["ntp_server"].drift_type is DriftType.REMOVED
    assert by_key["ntp_server"].classification is DriftClassification.DEFAULT_RESTORED


def test_unknown_default_never_classifies_as_restored(store, counters):
    """banner default is UNKNOWN (not_recorded) ⇒ honesty beats convenience."""
    store.create("dev-1", {"banner": "custom"}, TS)
    bid = store.for_device("dev-1")[1].baseline_id
    report = engine(store, counters).evaluate(
        bid, {"banner": "something-else"}, platform_key="test/os")
    assert report.records[0].classification is DriftClassification.UNMANAGED_DRIFT


def test_unmanaged_drift_counts_as_unauthorized_change(store, counters):
    engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.9.9.9", "syslog_host": "10.0.0.9", "ssh_enabled": True})
    assert counters.value("unauthorized_changes") == 1
    assert "unmanaged" in next(counters.reasons("unauthorized_changes"))


def test_no_defaults_db_still_classifies_unmanaged(store, counters):
    report = ReconciliationEngine(store, defaults=None, counters=counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.0.0.1", "syslog_host": "10.0.0.9", "ssh_enabled": True},
        platform_key="test/os")
    assert report.records[0].classification is DriftClassification.UNMANAGED_DRIFT


def test_hints_are_structured_codes_not_commands():
    for hint in REMEDIATION_HINTS.values():
        assert hint.isupper() or "_" in hint
        assert " " not in hint  # codes, never shell/device command text (L11)


def test_report_counts_by_classification(store, counters):
    report = engine(store, counters).evaluate(
        store.for_device("dev-1")[0].baseline_id,
        {"ntp_server": "10.0.0.1", "syslog_host": "10.0.0.9", "ssh_enabled": False},
        platform_key="test/os")
    assert report.count(DriftClassification.DEFAULT_RESTORED) == 1
    assert report.count(DriftClassification.UNMANAGED_DRIFT) == 1
    assert report.count(DriftClassification.MANAGED) == 0
