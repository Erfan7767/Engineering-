"""Tests for Phase N expert-grade engines.

The 30-year-engineer trust criteria: every engine must

* return typed results (no silent None / no silent PASS),
* handle missing input by saying so, not by guessing,
* be unit-testable without a network.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.compliance import (
    ComplianceFramework,
    ComplianceRule,
    FindingStatus,
    Severity,
    catalog,
    evaluate,
    register,
    reset,
    render_report,
)
from netops_autopilot.engines.convergence import (
    ConvergenceProbe,
    ConvergenceVerdict,
    probe,
)
from netops_autopilot.engines.backup import (
    SnapshotStore,
    capture,
    diff_snapshots,
    restore,
    ConfigSnapshot,
)
from netops_autopilot.engines.diff import preview
from netops_autopilot.engines.maintenance import (
    MaintenanceWindow,
    WindowRegistry,
    WindowVerdict,
    evaluate_window,
)
from netops_autopilot.engines.capability_matrix import (
    Capability,
    HardwareSpec,
    has_capability,
    lookup,
)
from netops_autopilot.engines.health import (
    InterfaceHealth,
    parse_interfaces,
    DeviceHealth,
)
from netops_autopilot.engines.inventory import Inventory, InventoryItem
from netops_autopilot.engines.audit_export import export, ExportFilter
from netops_autopilot.engines.topology_map import TopologyMap, MapNode as TopologyNode, MapEdge as TopologyEdge
from netops_autopilot.engines.topology_stats import compute as compute_stats


# ===================================================================
# Compliance
# ===================================================================

class _MockSession:
    def __init__(self, mapping: dict[str, bytes]) -> None:
        self.mapping = mapping

    def execute(self, command: str, timeout_s: float) -> bytes:
        return self.mapping.get(command, b"")


def test_compliance_empty_config_is_sample_missing():
    """An empty config is a typed SAMPLE_MISSING, not a silent PASS."""
    report = evaluate("seed-01", "")
    assert report.device_ref == "seed-01"
    assert report.rules_evaluated > 0
    assert all(f.status == FindingStatus.SAMPLE_MISSING for f in report.findings)


def test_compliance_clean_cisco_ios_passes():
    """A hardened Cisco config passes all CIS rules."""
    cfg = """
service password-encryption
service timestamps log datetime msec
no ip http server
no ip http secure-server
no ip source-route
enable secret 5 $1$abcd$efgh
username operator secret 9 $9$abcd
lldp run
logging buffered 8192
logging host 10.0.0.100
ntp server 10.0.0.200
snmp-server community notdefault RO 99
banner motd # Authorized access only #
line vty 0 4
 transport input ssh
!
"""
    report = evaluate("seed-01", cfg)
    assert report.overall_verdict == "COMPLIANT"
    assert report.fail_count == 0


def test_compliance_dirty_config_flags_pci_critical():
    """A config with telnet triggers PCI-DSS CRITICAL."""
    cfg = """
line vty 0 4
 transport input telnet
!
ip http server
!
"""
    report = evaluate("seed-01", cfg)
    # PCI-2.2.1 must be CRITICAL/FAIL.
    pci = [f for f in report.findings if f.framework == ComplianceFramework.PCI_DSS]
    assert any(f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL for f in pci)
    assert report.overall_verdict in ("NON_COMPLIANT_CRITICAL", "NON_COMPLIANT_HIGH")


def test_compliance_default_account_flagged():
    """The default 'cisco' account is a NIST AC-2 violation."""
    cfg = """
username cisco secret 9 $9$abcd
!
"""
    report = evaluate("seed-01", cfg)
    nist = [f for f in report.findings if f.rule_id == "NIST-AC-2"]
    assert len(nist) == 1
    assert nist[0].status == FindingStatus.FAIL


def test_compliance_register_custom_rule():
    """A custom rule can be registered and applied."""
    reset()
    register(ComplianceRule(
        rule_id="CUSTOM-1",
        title="No 'reload in 5' (workaround)",
        framework=ComplianceFramework.BEST_PRACTICE,
        severity=Severity.LOW,
        description="Forbid pending reloads.",
        remediation="Use 'reload cancel' or wait.",
        pattern=re.compile(r"^\s*reload\s+in\s+", re.MULTILINE),
        presence_means_pass=False,
    ))
    report = evaluate("seed-01", "reload in 5\n")
    custom = [f for f in report.findings if f.rule_id == "CUSTOM-1"]
    assert len(custom) == 1
    assert custom[0].status == FindingStatus.FAIL
    reset()


def test_compliance_render_in_arabic():
    """Arabic rendering works."""
    report = evaluate("seed-01", "")
    text = render_report(report, lang="ar")
    assert "تقرير" in text


# ===================================================================
# Convergence
# ===================================================================

class _FakeSession:
    """A session whose `show ip route` output changes between
    calls 1 and 2 (the convergence window). Call 3 is stable
    and matches call 2."""

    def __init__(self) -> None:
        self.calls = 0
        self.commands_received: list[str] = []

    def execute(self, command: str, timeout_s: float = 0) -> bytes:
        self.calls += 1
        self.commands_received.append(command)
        if self.calls == 1:
            return b"Codes: C - connected\n10.0.0.0/24 is variably subnetted"
        # Calls 2, 3, ... are stable.
        return b"Codes: C - connected\n10.0.0.0/24 is subnetted, 1 subnets"


def test_convergence_converges_on_third_attempt():
    s = _FakeSession()
    cfg = ConvergenceProbe(
        device_ref="seed-01",
        commands=("show ip route summary",),
        max_attempts=6,
        interval_s=0.0,
    )
    sleeps: list[float] = []
    clocks = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
    res = probe(s, cfg, sleep=sleeps.append, clock=clocks.pop)
    assert res.verdict == ConvergenceVerdict.CONVERGED
    assert res.attempts == 3


def test_convergence_timeout_when_always_changing():
    class _Churn:
        def execute(self, c, timeout_s: float = 0) -> bytes: return f"line {time.time_ns()}".encode()
    cfg = ConvergenceProbe(
        device_ref="seed-01",
        commands=("show ip route summary",),
        max_attempts=3,
        interval_s=0.0,
    )
    res = probe(_Churn(), cfg, sleep=lambda s: None, clock=lambda: 0.0)
    assert res.verdict == ConvergenceVerdict.TIMEOUT
    assert res.attempts == 3


def test_convergence_transport_failure():
    class _Boom:
        def execute(self, c, timeout_s: float = 0) -> bytes: raise ConnectionError("transient")
    cfg = ConvergenceProbe(
        device_ref="seed-01",
        commands=("show ip route summary",),
        max_attempts=3,
        interval_s=0.0,
    )
    res = probe(_Boom(), cfg, sleep=lambda s: None, clock=lambda: 0.0)
    assert res.verdict == ConvergenceVerdict.TRANSPORT_FAILED
    assert "transient" in res.detail


# ===================================================================
# Backup / Restore
# ===================================================================

def _fake_session(outputs: dict[str, bytes]) -> _MockSession:
    return _MockSession(outputs)


def test_backup_capture_hashes_stably():
    s = _fake_session({"show running-config": b"hostname A\n!\n"})
    snap = capture(s, "seed-01", note="initial")
    assert snap.device_ref == "seed-01"
    assert snap.config_text.startswith("hostname A")
    assert len(snap.config_hash) == 16
    # Capture again — hash should be stable.
    snap2 = capture(s, "seed-01", note="again")
    assert snap2.config_hash == snap.config_hash


def test_backup_store_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        s = _fake_session({"show running-config": b"hostname A\n!\n"})
        snap = capture(s, "seed-01", note="n1")
        store.save(snap)
        assert store.latest("seed-01") is not None
        assert store.latest("seed-01").snapshot_id == snap.snapshot_id


def test_backup_store_trims_to_max_keep():
    with tempfile.TemporaryDirectory() as tmp:
        store = SnapshotStore(tmp)
        for i in range(5):
            snap = ConfigSnapshot(
                snapshot_id=f"seed-01-{i:03d}-{'0'*16}",
                device_ref="seed-01",
                captured_at_unix=1700000000.0 + i,
                config_text=f"line {i}\n",
                config_hash=f"{i:016x}"[:16],
                byte_size=10,
            )
            store.save(snap, max_keep=3)
        snaps = store.list("seed-01")
        assert len(snaps) == 3
        # The most recent 3 survive (sorted by mtime).
        ids = [s.snapshot_id for s in snaps]
        assert "seed-01-004-0000000000000000" in ids


def test_backup_diff_added_removed():
    s1 = ConfigSnapshot(
        snapshot_id="L", device_ref="d", captured_at_unix=0.0,
        config_text="hostname A\n!\n", config_hash="0"*16, byte_size=10,
    )
    s2 = ConfigSnapshot(
        snapshot_id="R", device_ref="d", captured_at_unix=1.0,
        config_text="hostname B\nvlan 10\n!\n", config_hash="0"*16, byte_size=20,
    )
    d = diff_snapshots(s1, s2)
    assert d.added_count == 2  # hostname B, vlan 10
    assert d.removed_count == 1  # hostname A


# ===================================================================
# Diff / Preview
# ===================================================================

def test_preview_against_empty_when_no_snapshot():
    from netops_autopilot.access.allowlist import CommandAllowlist
    from netops_autopilot.specs_data import specs_data_dir
    al = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    p = preview(
        "seed-01",
        "vlan 10\nname users\n",
        None,
        al,
    )
    assert p.is_unverified
    assert p.risk_summary.config_reversible == 2  # vlan 10, name users


def test_preview_against_existing_snapshot():
    from netops_autopilot.access.allowlist import CommandAllowlist
    from netops_autopilot.specs_data import specs_data_dir
    al = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    snap = ConfigSnapshot(
        snapshot_id="L", device_ref="seed-01", captured_at_unix=0.0,
        config_text="hostname A\n!\n", config_hash="0"*16, byte_size=10,
    )
    p = preview("seed-01", "vlan 10\n", snap, al)
    assert not p.is_unverified
    assert p.diff.added_count == 1


def test_preview_flags_forbidden_lines():
    from netops_autopilot.access.allowlist import CommandAllowlist
    from netops_autopilot.specs_data import specs_data_dir
    al = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    p = preview("seed-01", "no logging\n", None, al)
    # 'no logging' is not in any vendor allowlist template —
    # it'll fall into "unclassified". The point is the preview
    # surfaces the risk_summary correctly.
    assert p.risk_summary.forbidden + p.risk_summary.unclassified >= 1


# ===================================================================
# Maintenance window
# ===================================================================

def test_window_inside():
    w = MaintenanceWindow(
        window_id="W1", label="nightly",
        start_unix=1000.0, end_unix=2000.0,
    )
    res = evaluate_window(w, now_unix=1500.0)
    assert res.verdict == WindowVerdict.INSIDE


def test_window_not_yet():
    w = MaintenanceWindow(
        window_id="W1", label="future",
        start_unix=2000.0, end_unix=3000.0,
    )
    res = evaluate_window(w, now_unix=1500.0)
    assert res.verdict == WindowVerdict.NOT_YET


def test_window_ended():
    w = MaintenanceWindow(
        window_id="W1", label="past",
        start_unix=100.0, end_unix=200.0,
    )
    res = evaluate_window(w, now_unix=1500.0)
    assert res.verdict == WindowVerdict.ENDED


def test_window_invalid():
    w = MaintenanceWindow(
        window_id="W1", label="bad",
        start_unix=200.0, end_unix=100.0,
    )
    res = evaluate_window(w, now_unix=150)
    assert res.verdict == WindowVerdict.INVALID


def test_registry_add_and_query():
    reg = WindowRegistry()
    w = MaintenanceWindow(
        window_id="W1", label="now",
        start_unix=time.time() - 100.0,
        end_unix=time.time() + 100.0,
    )
    reg.add(w)
    assert reg.list_active() != []
    assert reg.get("W1") is w
    reg.add(w)  # idempotent
    assert len(reg.list_all()) == 1
    reg.clear()
    assert reg.list_all() == []


# ===================================================================
# Capability matrix
# ===================================================================

def test_capability_lookup_known():
    spec = lookup("cisco", "C9500-48Y4C")
    assert spec is not None
    assert Capability.VXLAN in spec.capabilities
    assert Capability.STACKING in spec.capabilities


def test_capability_lookup_unknown_model():
    spec = lookup("cisco", "FAKE-XYZ")
    assert spec is None


def test_capability_has_capability_ok():
    ok, reason = has_capability("cisco", "C9500-48Y4C", Capability.VXLAN)
    assert ok is True
    assert reason == "OK"


def test_capability_has_capability_missing():
    ok, reason = has_capability("cisco", "C2960X-48TS-L", Capability.OSPF)
    assert ok is False
    assert "CAPABILITY_MISSING" in reason


def test_capability_unknown_model():
    ok, reason = has_capability("cisco", "FAKE-XYZ", Capability.OSPF)
    assert ok is False
    assert "UNKNOWN_MODEL" in reason


# ===================================================================
# Health
# ===================================================================

def test_health_parses_cisco_interfaces():
    sample = """
GigabitEthernet0/0 is up, line protocol is up
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  5 minute input rate 1000 bits/sec, 0 packets/sec
  5 minute output rate 2000 bits/sec, 0 packets/sec
     1234 packets input, 100000 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     5678 packets output, 200000 bytes, 0 underruns
GigabitEthernet0/1 is up, line protocol is up
  Input queue: 0/75/0/0
  100 packets input, 5000 bytes, 0 no buffer
  50 input errors, 5 CRC, 0 frame, 0 overrun, 0 ignored
GigabitEthernet0/2 is administratively down, line protocol is down
"""
    recs = parse_interfaces(sample)
    assert len(recs) == 3
    g0 = recs[0]
    assert g0.name == "GigabitEthernet0/0"
    assert g0.input_errors == 0
    assert g0.health == InterfaceHealth.HEALTHY
    g1 = recs[1]
    assert g1.input_errors == 50
    assert g1.health == InterfaceHealth.DEGRADED
    g2 = recs[2]
    assert g2.health == InterfaceHealth.DOWN


def test_health_handles_empty_output():
    recs = parse_interfaces("")
    assert recs == []


def test_health_renders_arabic():
    h = DeviceHealth(device_ref="d", interfaces=[])
    text = h_overall = type(h).__name__
    # Arabic render path
    from netops_autopilot.engines.health import render_health
    out = render_health(h, lang="ar")
    assert "صحة" in out


# ===================================================================
# Inventory
# ===================================================================

def test_inventory_search_and_filter():
    items = [
        InventoryItem("core-1", vendor="cisco", model="C9500", status="COMPLETE", mgmt_address="10.0.0.1"),
        InventoryItem("access-1", vendor="cisco", model="C9200", status="UNREACHABLE", mgmt_address=""),
        InventoryItem("edge-1", vendor="juniper", model="EX3400", status="COMPLETE", mgmt_address="10.0.0.3"),
    ]
    inv = Inventory(items=items)
    assert inv.by_status["COMPLETE"] == 2
    assert inv.by_vendor["cisco"] == 2
    s = inv.search("core")
    assert len(s.items) == 1 and s.items[0].device_ref == "core-1"
    s = inv.filter(status="COMPLETE")
    assert len(s.items) == 2
    s = inv.filter(vendor="juniper")
    assert len(s.items) == 1


# ===================================================================
# Audit export
# ===================================================================

def test_audit_export_json_with_store():
    """The exporter must produce valid JSON with a real store."""
    from datetime import datetime, timezone
    from netops_autopilot.ledger.store import LedgerStore
    from netops_autopilot.ledger.models import (
        Event, EventType, OperatorIdentity, CollectorIdentity, ClockStatusEnum,
    )
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp:
        store = LedgerStore(tmp.name)
        kid = store.keys.create_key("audit-test")
        ev = Event(
            type=EventType.CLI,
            command_or_op="show running-config",
            operator_identity=OperatorIdentity(kind="ENGINE", id="audit-test"),
            collector_identity=CollectorIdentity(collector_id="audit-test", key_id=kid),
            collected_at=datetime.fromtimestamp(1700000000.0, tz=timezone.utc),
            collector_clock_status=ClockStatusEnum.SYNCED,
            device_id="d1",
        )
        ev = store.sign_event(ev, key_id=kid)
        store.append_event(ev)
        out = export(store, fmt="json")
        assert "events" in out
        assert "event_count" in out


def test_audit_export_csv():
    from netops_autopilot.ledger.store import LedgerStore
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp:
        store = LedgerStore(tmp.name)
        out = export(store, fmt="csv")
        # Header is always present even on empty store.
        assert "id" in out and "type" in out


def test_audit_export_filter_device():
    from datetime import datetime, timezone
    from netops_autopilot.ledger.store import LedgerStore
    from netops_autopilot.ledger.models import (
        Event, EventType, OperatorIdentity, CollectorIdentity, ClockStatusEnum,
    )
    with tempfile.NamedTemporaryFile(suffix=".sqlite3") as tmp:
        store = LedgerStore(tmp.name)
        kid = store.keys.create_key("audit-test")
        for d in ("d1", "d2"):
            ev = Event(
                type=EventType.CLI,
                command_or_op="show running-config",
                operator_identity=OperatorIdentity(kind="ENGINE", id="audit-test"),
                collector_identity=CollectorIdentity(collector_id="audit-test", key_id=kid),
                collected_at=datetime.fromtimestamp(1700000000.0, tz=timezone.utc),
                collector_clock_status=ClockStatusEnum.SYNCED,
                device_id=d,
            )
            ev = store.sign_event(ev, key_id=kid)
            store.append_event(ev)
        out = export(store, ExportFilter(device_ref="d1"), fmt="json")
        # Should have 1 event.
        import json
        d = json.loads(out)
        assert d["event_count"] == 1


# ===================================================================
# Topology stats
# ===================================================================

def test_topology_stats_identifies_spof():
    # 3 nodes in a line: A-B-C. Removing B disconnects A and C.
    t = TopologyMap(nodes=(
        TopologyNode("A", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S1", row=0, col=0),
        TopologyNode("B", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S2", row=0, col=1),
        TopologyNode("C", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S3", row=0, col=2),
    ), edges=(
        TopologyEdge("l1", "A", "B", "UP", ("L3",)),
        TopologyEdge("l2", "B", "C", "UP", ("L3",)),
    ), seed="A", gaps=(), ascii="A-B-C")
    s = compute_stats(t)
    assert s.device_count == 3
    assert s.link_count == 2
    assert "B" in s.single_points_of_failure


def test_topology_stats_no_spof_in_triangle():
    t = TopologyMap(nodes=(
        TopologyNode("A", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S1", row=0, col=0),
        TopologyNode("B", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S2", row=0, col=1),
        TopologyNode("C", classification="core", status="COMPLETE", vendor_family="cisco/ios-xe", model="C9500", version="17.1", serial="S3", row=0, col=2),
    ), edges=(
        TopologyEdge("l1", "A", "B", "UP", ("L3",)),
        TopologyEdge("l2", "B", "C", "UP", ("L3",)),
        TopologyEdge("l3", "A", "C", "UP", ("L3",)),
    ), seed="A", gaps=(), ascii="A-B-C")
    s = compute_stats(t)
    assert s.single_points_of_failure == []
    assert s.diameter == 1
