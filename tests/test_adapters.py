"""Adapter layer contract (ADR-0001): nine interfaces, typed NOT_SUPPORTED,
deterministic registry resolution, no exceptions-as-capabilities."""

import pytest

from netops_autopilot.adapters.interfaces import (
    ALL_ADAPTER_INTERFACES,
    AccessAdapter,
    CapabilityState,
    ConfigAdapter,
    DiscoveryAdapter,
    LifecycleAdapter,
    MonitoringAdapter,
    RecoveryAdapter,
    RollbackAdapter,
    VerificationAdapter,
    WirelessControlPlaneAdapter,
    not_supported,
)
from netops_autopilot.adapters.registry import AdapterMatch, AdapterRegistry
from netops_autopilot.core.failures import Failure, FailureClass


def test_exactly_nine_interfaces():
    assert len(ALL_ADAPTER_INTERFACES) == 9
    names = {cls.__name__ for cls in ALL_ADAPTER_INTERFACES}
    assert names == {
        "AccessAdapter", "DiscoveryAdapter", "ConfigAdapter", "RollbackAdapter",
        "RecoveryAdapter", "VerificationAdapter", "MonitoringAdapter",
        "LifecycleAdapter", "WirelessControlPlaneAdapter",
    }


def test_unimplemented_methods_announce_not_supported_typed():
    """Missing capability is a typed state (T2), never a raw exception."""
    rb = RollbackAdapter()
    with pytest.raises(Failure) as exc:
        rb.prepare("dev-1", "ARCHIVE_CONFIGURE_REPLACE")
    assert exc.value.cls is FailureClass.BLOCKED
    assert exc.value.causes[0].startswith("NOT_SUPPORTED")

    cfg = ConfigAdapter()
    with pytest.raises(Failure):
        cfg.capture_running_config("dev-1")
    mon = MonitoringAdapter()
    with pytest.raises(Failure):
        mon.bind_collectors("dev-1")
    wl = WirelessControlPlaneAdapter()
    with pytest.raises(Failure):
        wl.adopt("ap-1")


def test_access_adapter_defaults_fail_safe_on_human_sessions():
    """Cannot prove exclusivity ⇒ assume a human may be attached (TH-13)."""
    assert AccessAdapter().human_session_active("dev-1") is True


def test_recovery_l5_always_requires_human_gate_token():
    rec = RecoveryAdapter()
    with pytest.raises(Failure) as exc:
        rec.execute_level("dev-1", level=5)
    assert "DESTRUCTIVE_GATE_REQUIRED" in exc.value.causes[0]
    assert rec.level_supported("dev-1", 3) is CapabilityState.NOT_SUPPORTED


def test_capability_default_is_unknown():
    assert DiscoveryAdapter().capability("discovery_layer:L3") is CapabilityState.UNKNOWN


class _FakeCisco:
    vendor_family = "cisco/ios-xe"


class _FakeRouterOs:
    vendor_family = "mikrotik/routeros"


def test_registry_resolves_by_vendor_and_os():
    reg = AdapterRegistry()
    reg.register(AdapterMatch(vendor="cisco", os="ios-xe"), _FakeCisco)
    reg.register(AdapterMatch(vendor="mikrotik", os="routeros"), _FakeRouterOs)
    assert isinstance(reg.resolve(vendor="cisco", os="ios-xe"), _FakeCisco)
    assert isinstance(reg.resolve(vendor="mikrotik", os="routeros"), _FakeRouterOs)
    # Unidentified tuple ⇒ None ⇒ engine treats as NOT_SUPPORTED (T2).
    assert reg.resolve(vendor="unknown-vendor") is None
    assert reg.resolve(vendor="cisco", os="nxos") is None


def test_registry_specificity_model_beats_vendor_wide():
    reg = AdapterRegistry()
    reg.register(AdapterMatch(vendor="cisco"), lambda: "generic")
    reg.register(AdapterMatch(vendor="cisco", os="ios-xe", model_patterns=("C83*",)), lambda: "specific")
    assert reg.resolve(vendor="cisco", os="ios-xe", model="C8300-1N-4T") == "specific"
    assert reg.resolve(vendor="cisco", os="ios-xe", model="ISR4331") == "generic"


def test_registry_os_specific_beats_late_generic_registration():
    """Late generic registrations cannot shadow specific ones (ADR-0001)."""
    reg = AdapterRegistry()
    reg.register(AdapterMatch(vendor="cisco", os="ios-xe"), lambda: "specific")
    reg.register(AdapterMatch(vendor="cisco"), lambda: "generic-late")
    assert reg.resolve(vendor="cisco", os="ios-xe") == "specific"
    assert reg.resolve(vendor="cisco", os=None) == "generic-late"


def test_known_vendors_listing():
    reg = AdapterRegistry()
    reg.register(AdapterMatch(vendor="juniper", os="junos"), lambda: None)
    reg.register(AdapterMatch(vendor="fortinet", os="fortios"), lambda: None)
    assert reg.known_vendors() == ["fortinet", "juniper"]


def test_not_supported_helper_shape():
    f = not_supported("open_session:SERIAL_CONSOLE")
    assert f.cls is FailureClass.BLOCKED
    assert "T2" in f.causes[0]
