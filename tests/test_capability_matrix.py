"""E06 Capability Matrices: typed answers, conservative versions, T2 gates."""

import pytest

from netops_autopilot.engines.capability import (
    CapabilityEngine,
    CapabilityValue,
    RecoveryStatus,
    parse_version_tuple,
    version_satisfies,
)


@pytest.fixture(scope="module")
def engine():
    return CapabilityEngine.load_builtin()


def test_all_six_v1_families_present(engine):
    families = {engine.platform_entry(k) is not None for k in (
        "cisco/ios-xe", "mikrotik/routeros", "juniper/junos",
        "fortinet/fortios", "aruba/arubaos", "ubiquiti/unifi")}
    assert families == {True}


def test_documented_discovery_yes_is_typed(engine):
    assert engine.lookup("cisco/ios-xe", "17.9.4a", "vlan", "discover") is CapabilityValue.YES
    assert engine.lookup("mikrotik/routeros", "7.14.3", "ospf", "discover") is CapabilityValue.YES


def test_configure_is_unknown_until_lab_evidence(engine):
    """Honest seed: no configure YES exists before lab verification (T2)."""
    for family in ("cisco/ios-xe", "mikrotik/routeros", "juniper/junos",
                   "fortinet/fortios", "aruba/arubaos", "ubiquiti/unifi"):
        for feature in engine.features_of(family):
            assert engine.lookup(family, "99.99", feature, "configure") is CapabilityValue.UNKNOWN, (family, feature)


def test_unknown_is_not_plannable(engine):
    assert engine.is_plannable("cisco/ios-xe", "17.9.4a", "vlan") is False
    # And NO/PARTIAL are not plannable either — only YES would be.
    assert not CapabilityValue.PARTIAL.plannable
    assert not CapabilityValue.NO.plannable
    assert not CapabilityValue.UNKNOWN.plannable


def test_unknown_platform_feature_operation_all_typed_unknown(engine):
    assert engine.lookup("vendor/none", "1.0", "vlan", "discover") is CapabilityValue.UNKNOWN
    assert engine.lookup("cisco/ios-xe", "17.9.4a", "no_such_feature", "discover") is CapabilityValue.UNKNOWN
    assert engine.lookup("cisco/ios-xe", "17.9.4a", "vlan", "no_such_op") is CapabilityValue.UNKNOWN


def test_version_constraint_below_bound_is_unknown(engine):
    assert engine.lookup("cisco/ios-xe", "16.8.1", "vlan", "discover") is CapabilityValue.UNKNOWN
    assert engine.lookup("cisco/ios-xe", "16.9", "vlan", "discover") is CapabilityValue.YES


def test_unparseable_version_is_unknown_never_match(engine):
    assert engine.lookup("cisco/ios-xe", "garbage-version", "vlan", "discover") is CapabilityValue.UNKNOWN


def test_unifi_version_constraint_unknown_means_unknown(engine):
    """Constraint UNKNOWN ⇒ lookup UNKNOWN regardless of provided version."""
    assert engine.lookup("ubiquiti/unifi", "7.0", "vlan", "discover") is CapabilityValue.UNKNOWN


def test_version_parser_is_conservative():
    assert parse_version_tuple("17.09.04a") == (17, 9, 4)
    assert parse_version_tuple("21.4R3-S5") == (21, 4)
    assert parse_version_tuple("7.14.3 (stable)") == (7, 14, 3)
    assert parse_version_tuple("no-digits") is None
    assert version_satisfies("17.9.4a", ">=16.9") is True
    assert version_satisfies("16.8.9", ">=16.9") is False
    assert version_satisfies("garbage", ">=16.9") is None
    assert version_satisfies("17.9", "UNKNOWN") is None
    assert version_satisfies("17.9", "<16.9") is None  # unsupported operator ⇒ conservative None


def test_feature_record_carries_basis_and_note(engine):
    rec = engine.feature_record("mikrotik/routeros", "acl")
    assert rec is not None
    assert rec.basis == "documented"
    assert rec.note  # RouterOS firewall model caveat recorded
    assert rec.values["discover"] is CapabilityValue.PARTIAL
    assert engine.feature_record("mikrotik/routeros", "nope") is None


def test_recovery_matrix_answers(engine):
    assert engine.recovery_lookup("mikrotik/routeros", "safe_mode").status is RecoveryStatus.SUPPORTED
    # Policy-level NOT_SUPPORTED (session-scoped history), not absence:
    hist = engine.recovery_lookup("mikrotik/routeros", "system_history")
    assert hist.status is RecoveryStatus.NOT_SUPPORTED and "session-scoped" in hist.note
    assert engine.recovery_lookup("aruba/arubaos", "checkpoint_rollback").status is RecoveryStatus.UNKNOWN
    assert engine.recovery_lookup("ubiquiti/unifi", "device_local_rollback").status is RecoveryStatus.NOT_SUPPORTED
    assert engine.recovery_lookup("vendor/none", "safe_mode").status is RecoveryStatus.UNKNOWN


def test_recovery_methods_listing_is_deterministic(engine):
    methods = engine.recovery_methods("cisco/ios-xe")
    assert methods == sorted(methods)
    assert "archive_configure_replace" in methods
