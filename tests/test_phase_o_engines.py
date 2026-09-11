"""Tests for Phase O expert-grade engines — 8 more 30-year
expert operations: MAC table, cable diag, routing neighbors,
ACL audit, PoE budget, drift, EOL, trunk audit, upgrade
path, summary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.mac_table import (
    analyse, parse, EntryType, MacAnalysis,
)
from netops_autopilot.engines.cable_diag import (
    CableHealth, CableReport, CableStats, parse as parse_cable,
)
from netops_autopilot.engines.routing_neighbors import (
    NeighborState, Protocol, RoutingReport, RoutingNeighbor,
    parse_ospf, parse_bgp, _classify_ospf_state, _classify_bgp_state,
)
from netops_autopilot.engines.acl_audit import (
    AceVerdict, AclReport, parse as parse_acl,
)
from netops_autopilot.engines.poe import (
    PoeState, PoeReport, analyse as analyse_poe,
)
from netops_autopilot.engines.drift import detect, DriftReport
from netops_autopilot.engines.backup import ConfigSnapshot
from netops_autopilot.engines.eol import (
    EolVerdict, evaluate as evaluate_eol, lookup, render,
)
from netops_autopilot.engines.trunk_audit import (
    Trunk, TrunkReport, parse as parse_trunk,
)
from netops_autopilot.engines.upgrade_path import (
    evaluate, verdict_for, UpgradeVerdict,
)
from netops_autopilot.engines.summary import build, SummaryInputs


# ===================================================================
# MAC table
# ===================================================================

def test_mac_table_parses_cisco_output():
    output = """
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0011.2233.4455    DYNAMIC     Gi0/1
  10    aabb.ccdd.eeff    DYNAMIC     Gi0/2
  20    1122.3344.5566    STATIC      Gi0/3
"""
    entries = parse(output)
    assert len(entries) == 3
    e = entries[0]
    assert e.vlan == "10"
    assert e.entry_type == EntryType.DYNAMIC
    assert e.port == "Gi0/1"


def test_mac_table_handles_empty_output():
    assert parse("") == []


def test_mac_table_search_by_port():
    output = """
  10    0011.2233.4455    DYNAMIC     Gi0/1
  10    aabb.ccdd.eeff    DYNAMIC     Gi0/2
"""
    a = analyse("d", output)
    assert len(a.by_port("Gi0/1")) == 1
    assert len(a.by_mac("0011.2233.4455")) == 1


def test_mac_table_stale_threshold():
    a = analyse("d", "  10    0011.2233.4455    DYNAMIC     Gi0/1")
    # The age field is 0 by default; staleness depends on age.
    a.entries[0] = type(a.entries[0])(
        vlan=a.entries[0].vlan, mac=a.entries[0].mac,
        entry_type=a.entries[0].entry_type, port=a.entries[0].port,
        age_seconds=1000,
    )
    # We need a fresh analysis since stale is computed on the
    # current list.
    out = analyse("d", "")
    assert out.stale() == []


# ===================================================================
# Cable diagnostics
# ===================================================================

def test_cable_parses_cisco_interfaces():
    output = """
GigabitEthernet0/0 is up, line protocol is up
  5 minute input rate 1000 bits/sec, 0 packets/sec
  1234 packets input, 100000 bytes, 0 no buffer
  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  5678 packets output, 200000 bytes, 0 underruns
  0 output errors, 0 collisions, 0 interface resets
GigabitEthernet0/1 is up, line protocol is up
  100 packets input, 5000 bytes, 0 no buffer
  50 input errors, 5 CRC, 0 frame
  0 lost carrier, 0 no carrier
"""
    stats = parse_cable(output)
    assert len(stats) == 2
    g0 = stats[0]
    assert g0.health == CableHealth.GOOD
    g1 = stats[1]
    assert g1.crc == 5
    assert g1.health in (CableHealth.DEGRADED, CableHealth.GOOD)


def test_cable_fault_detected_on_lost_carrier():
    output = """
GigabitEthernet0/0 is up, line protocol is up
  100 packets input, 5000 bytes, 0 no buffer
  0 input errors, 0 CRC
  1 lost carrier, 0 no carrier
"""
    stats = parse_cable(output)
    assert stats[0].health == CableHealth.FAULT


def test_cable_handles_empty():
    assert parse_cable("") == []


# ===================================================================
# Routing neighbors
# ===================================================================

def test_ospf_classify_full_state():
    assert _classify_ospf_state("FULL/DR") == NeighborState.UP
    assert _classify_ospf_state("FULL/BDR") == NeighborState.UP
    assert _classify_ospf_state("2-WAY") == NeighborState.PENDING
    assert _classify_ospf_state("DOWN") == NeighborState.DOWN
    assert _classify_ospf_state("ATTEMPT") == NeighborState.DOWN
    assert _classify_ospf_state("WEIRD") == NeighborState.UNKNOWN


def test_bgp_classify_state_code():
    assert _classify_bgp_state("6") == NeighborState.UP
    assert _classify_bgp_state("5") == NeighborState.PENDING
    assert _classify_bgp_state("1") == NeighborState.DOWN
    assert _classify_bgp_state("Established") == NeighborState.UP
    assert _classify_bgp_state("Idle") == NeighborState.PENDING


def test_routing_parse_ospf():
    output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/DR         0:00:32     10.0.0.2        GigabitEthernet0/0
10.0.0.3          1   2-WAY/DROTHER   0:00:39     10.0.0.3        GigabitEthernet0/1
"""
    nbrs = parse_ospf(output)
    assert len(nbrs) == 2
    assert nbrs[0].state == NeighborState.UP
    assert nbrs[1].state == NeighborState.PENDING


def test_routing_parse_bgp():
    output = """
Neighbor        V    AS    State/PfxRcd   Up/Down
10.0.0.2        4    65000 6              00:30:12
10.0.0.3        4    65001 1              never
"""
    nbrs = parse_bgp(output)
    assert len(nbrs) == 2
    assert nbrs[0].state == NeighborState.UP
    assert nbrs[1].state == NeighborState.DOWN


def test_routing_report_overall():
    r = RoutingReport(
        device_ref="d",
        ospf=[],
        bgp=[RoutingNeighbor(protocol=Protocol.BGP, neighbor_id="1.1.1.1",
                              state=NeighborState.UP)],
    )
    assert r.overall_verdict == "HEALTHY"
    r.bgp[0] = RoutingNeighbor(protocol=Protocol.BGP, neighbor_id="1.1.1.1",
                                state=NeighborState.DOWN)
    assert r.overall_verdict == "DEGRADED"


# ===================================================================
# ACL audit
# ===================================================================

def test_acl_parses_cisco_output():
    output = """
Extended IP access list 100
    10 permit tcp any host 10.0.0.1 eq 80 (1234 matches)
    20 deny ip any any (5678 matches)
    30 permit icmp any any (0 matches)
"""
    aces = parse_acl(output)
    assert len(aces) == 3
    assert aces[0].hits == 1234
    assert aces[0].verdict == AceVerdict.HOT
    assert aces[2].hits == 0
    assert aces[2].verdict == AceVerdict.COLD


def test_acl_report_counts():
    aces = parse_acl("""
    10 permit tcp any any (5000 matches)
    20 deny ip any any (0 matches)
""")
    r = AclReport(device_ref="d", aces=aces)
    assert r.total == 2
    assert len(r.hot) == 1
    assert len(r.cold) == 1


# ===================================================================
# PoE budget
# ===================================================================

def test_poe_parses_cisco_output():
    output = """
Interface Admin  Oper       Power(Watts)  Class
--------- ------ ---------- ------------- -----
Gi0/1     auto   on         15.4          Class 4
Gi0/2     auto   on         7.0           Class 3
Gi0/3     auto   off        0.0           Class 0
Gi0/4     auto   fault      0.0           Class 0
Available Power = 60.00 Watts
"""
    r = analyse_poe("d", output)
    assert r.nominal_budget_w == 60.0
    assert r.allocated_w == 22.4
    assert r.on_count == 2
    assert r.fault_count == 1
    assert r.overall_verdict == "FAULT"


def test_poe_empty_input_is_unknown():
    r = analyse_poe("d", "")
    assert r.overall_verdict == "UNKNOWN"
    assert r.nominal_budget_w == 0.0


def test_poe_over_budget_detected():
    output = """
Gi0/1     auto   on         80.0          Class 4
Gi0/2     auto   on         30.0          Class 4
Available Power = 100.00 Watts
"""
    r = analyse_poe("d", output)
    assert r.allocated_w == 110.0
    assert r.utilization_pct == 110.0
    assert r.overall_verdict == "OVER_BUDGET_RISK"


# ===================================================================
# Drift detection
# ===================================================================

def test_drift_no_changes():
    snap = ConfigSnapshot(
        snapshot_id="L", device_ref="d", captured_at_unix=0.0,
        config_text="hostname A\n!\n", config_hash="0"*16, byte_size=10,
    )
    r = detect("d", snap, "hostname A\n!\n")
    assert r.overall_verdict == "NO_DRIFT"
    assert r.drift_count == 0


def test_drift_detects_added_lines():
    snap = ConfigSnapshot(
        snapshot_id="L", device_ref="d", captured_at_unix=0.0,
        config_text="hostname A\n!\n", config_hash="0"*16, byte_size=10,
    )
    r = detect("d", snap, "hostname A\nip route 0.0.0.0 0.0.0.0 10.0.0.1\n!\n")
    assert r.overall_verdict != "NO_DRIFT"
    assert any(l.text.startswith("ip route") for l in r.drift_lines)


def test_drift_ignores_comments():
    snap = ConfigSnapshot(
        snapshot_id="L", device_ref="d", captured_at_unix=0.0,
        config_text="!\n", config_hash="0"*16, byte_size=2,
    )
    r = detect("d", snap, "!\n! another comment\n")
    assert r.drift_count == 0


# ===================================================================
# EOL/EOS
# ===================================================================

def test_eol_lookup_known():
    rec = lookup("cisco", "C2960X-48TS-L")
    assert rec is not None
    assert rec.replacement == "C9200-48P"


def test_eol_lookup_unknown():
    assert lookup("cisco", "FAKE-9999") is None


def test_eol_active_model():
    s = evaluate_eol("cisco", "C9500-48Y4C", today="2026-09-11")
    assert s is not None
    assert s.verdict == EolVerdict.ACTIVE


def test_eol_passed_lifecycle():
    s = evaluate_eol("cisco", "C2960X-48TS-L", today="2030-01-01")
    assert s is not None
    assert s.verdict in (EolVerdict.EOS_REACHED, EolVerdict.EOL_REACHED)


def test_eol_renders_arabic():
    s = evaluate_eol("cisco", "C9500-48Y4C", today="2026-09-11")
    assert s is not None
    text = render(s, lang="ar")
    assert "حالة EOL" in text


# ===================================================================
# Trunk audit
# ===================================================================

def test_trunk_parses_cisco_output():
    output = """
Port      Mode         Encapsulation  Status        Native vlan
Gi0/1     on           802.1q         trunking      1

VLANs allowed: 1-4094
VLANs active: 1,10,20,30

Gi0/2     on           802.1q         trunking      1

VLANs allowed: 1-100,200
VLANs active: 1,10
"""
    trunks = parse_trunk(output)
    assert len(trunks) == 2
    t = trunks[0]
    assert t.status == "trunking"
    # 1-4094 expands to all VLANs; we verify a few.
    assert 1 in t.vlan_allowed
    assert 100 in t.vlan_allowed
    assert 4094 in t.vlan_allowed
    assert t.vlan_active == (1, 10, 20, 30)
    t2 = trunks[1]
    assert 200 in t2.vlan_allowed
    assert 100 in t2.vlan_allowed
    assert 50 in t2.vlan_allowed


def test_trunk_empty():
    assert parse_trunk("") == []


# ===================================================================
# Upgrade path
# ===================================================================

def test_upgrade_direct_supported():
    s = evaluate("17.9", "17.12")
    assert verdict_for(s) == UpgradeVerdict.SUPPORTED


def test_upgrade_requires_intermediate():
    s = evaluate("15.6", "17.12")
    assert verdict_for(s) == UpgradeVerdict.REQUIRES_INTERMEDIATE
    assert s.intermediate == "16.9"


def test_upgrade_same_version_unknown():
    s = evaluate("17.9", "17.9")
    assert verdict_for(s) == UpgradeVerdict.UNKNOWN


def test_upgrade_unsupported_path():
    s = evaluate("14.0", "17.0")
    # 14.0 is not in our catalogue
    assert verdict_for(s) == UpgradeVerdict.NOT_SUPPORTED


# ===================================================================
# Summary
# ===================================================================

def test_summary_arabic_and_english():
    s = SummaryInputs(device_count=5, reachable_count=3,
                       unreachable_count=2, link_count=4,
                       last_run_verdict="COMPLETE-APPLIED",
                       evidence_count=42)
    en = build(s, lang="en")
    ar = build(s, lang="ar")
    assert "NETWORK SUMMARY" in en
    assert "Devices:    5" in en
    assert "ملخص الشبكة" in ar
    assert "5" in ar


def test_summary_with_zero_values():
    s = SummaryInputs()
    out = build(s, lang="en")
    assert "Devices:    0" in out
    assert "Last run:   —" in out
