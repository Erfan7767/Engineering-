"""Day-0 classifier + ACCESS_LIMITED advisor: deterministic, never assumes."""

import os

import pytest

from netops_autopilot.access.day0 import (
    Day0State,
    classify_day0_state,
    suggest_access_path,
    _classifier_data,
)


@pytest.fixture(autouse=True)
def _reset_data_cache():
    _classifier_data.cache_clear()
    yield
    _classifier_data.cache_clear()


def test_classifier_data_file_loads():
    data = _classifier_data()
    assert set(data["families"]) == {"cisco/ios-xe", "routeros", "junos", "fortios", "arubaos", "unifi"}


def test_cisco_factory_default_marker():
    banner = b"--- System Configuration Dialog ---\nContinue with configuration dialog? [yes/no]:"
    assert classify_day0_state("cisco/ios-xe", banner) is Day0State.FACTORY_DEFAULT


def test_rommon_outranks_password_fragments_deterministically():
    banner = b"rommon 1 > login incorrect attempt logged\nrommon 2 >"
    assert classify_day0_state("cisco/ios-xe", banner) is Day0State.RECOVERY_REQUIRED


def test_password_locked_classified_over_blank():
    assert classify_day0_state("routeros", "login failed: incorrect password") is Day0State.PASSWORD_LOCKED


def test_unmatched_output_is_unknown_never_assumed():
    assert classify_day0_state("cisco/ios-xe", b"\x00garbage\xff") is Day0State.UNKNOWN
    assert classify_day0_state("junos", "hostname> ") is Day0State.UNKNOWN


def test_unregistered_family_is_unknown():
    assert classify_day0_state("mellanox", "--- System Configuration Dialog ---") is Day0State.UNKNOWN


def test_missing_data_file_is_unknown_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("DAY0_CLASSIFIERS_PATH", str(tmp_path / "absent.json"))
    assert classify_day0_state("cisco/ios-xe", "--- System Configuration Dialog ---") is Day0State.UNKNOWN


def test_unifi_has_no_criteria_yet():
    assert classify_day0_state("unifi", "anything") is Day0State.UNKNOWN


# ------------------------------------------------------------ access advisor
class _Registry(dict):
    @property
    def adapters(self):
        return self


def test_access_path_prefers_confirmed_then_sorted():
    evidence = {
        "10.99.0.9": {"chassis_match"},
        "10.99.0.2": {"confirmed_bidirectional", "name_match"},
        "10.99.0.3": {"confirmed_bidirectional", "chassis_match"},
        "": {"confirmed_bidirectional", "chassis_match"},  # empty never suggested
        "192.0.2.1": set(),  # zero ties excluded
    }
    suggestion = suggest_access_path(vendor_family="cisco/ios-xe", identity_evidence=evidence)
    assert suggestion.verdict == "MANAGEMENT_PATH_CANDIDATE"
    assert suggestion.addresses == ("10.99.0.2", "10.99.0.3", "10.99.0.9")
    assert "192.0.2.1" not in suggestion.addresses


def test_no_adapter_is_not_modeled_honest():
    suggestion = suggest_access_path(
        vendor_family="fortios",
        identity_evidence={"10.99.0.2": {"confirmed_bidirectional", "chassis_match"}},
        adapter_registry=_Registry(cisco=object()),
    )
    assert suggestion.verdict == "NOT_MODELED"


def test_no_candidates_is_human_task_with_reason():
    suggestion = suggest_access_path(vendor_family="junos", identity_evidence={"": {"chassis_match"}})
    assert suggestion.verdict == "HUMAN_TASK_REQUIRED"
    assert any("out-of-band" in r or "credentials" in r for r in suggestion.reasons)


def test_unknown_adapter_registry_degrades_to_candidate_with_honest_note():
    suggestion = suggest_access_path(
        vendor_family="arubaos",
        identity_evidence={"10.99.0.2": {"confirmed_bidirectional", "chassis_match"}},
        adapter_registry=None,
    )
    assert suggestion.verdict == "MANAGEMENT_PATH_CANDIDATE"
    assert any("UNKNOWN" in r for r in suggestion.reasons)
