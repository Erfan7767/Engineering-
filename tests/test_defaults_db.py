"""Platform Defaults DB: honesty rules enforced at load time."""

import pytest

from netops_autopilot.reconcile.defaults_db import DefaultValue, PlatformDefaults


def test_builtin_loads_and_covers_six_v1_families():
    db = PlatformDefaults.load_builtin()
    assert db.platforms() == [
        "aruba/arubaos", "cisco/ios-xe", "fortinet/fortios",
        "juniper/junos", "mikrotik/routeros", "ubiquiti/unifi",
    ]


def test_known_default_with_source():
    db = PlatformDefaults.load_builtin()
    v = db.default_for("cisco/ios-xe", "default_port_mode")
    assert v == DefaultValue(value="access", source="documented")
    assert not v.unknown


def test_unknown_default_is_typed_unknown():
    db = PlatformDefaults.load_builtin()
    v = db.default_for("cisco/ios-xe", "default_stp_mode")
    assert v is not None and v.unknown and v.source == "not_recorded"


def test_missing_platform_or_predicate_returns_none():
    """T2: absence of knowledge is None, never a fabricated default."""
    db = PlatformDefaults.load_builtin()
    assert db.default_for("vendor/nonexistent", "x") is None
    assert db.default_for("cisco/ios-xe", "no_such_predicate") is None


def test_loader_rejects_value_without_source():
    with pytest.raises(ValueError):
        PlatformDefaults({"platforms": {"v/os": {"p": {"value": 1}}}})


def test_loader_rejects_unknown_with_wrong_source():
    with pytest.raises(ValueError):
        PlatformDefaults({"platforms": {"v/os": {"p": {"value": "UNKNOWN", "source": "documented"}}}})


def test_loader_rejects_concrete_value_with_not_recorded():
    with pytest.raises(ValueError):
        PlatformDefaults({"platforms": {"v/os": {"p": {"value": 1, "source": "not_recorded"}}}})
