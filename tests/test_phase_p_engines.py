"""Tests for Phase P engines — 30-year expert deeper improvements.

Six new engines:
  P1. remediation — auto-remediation planner
  P2. real_device — SSH/paramiko device driver
  P3. protocols — LLDP / CDP / VTP / STP / DHCP parsers
  P4. root_cause — AI root-cause analyzer (rule-based)
  P5. distributed_discovery — async / bounded / retried
  P6. recommendations — 30-year expert tips
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.remediation import (
    ActionKind, RiskLevel, RemediationAction, RemediationPlan,
    plan_from_health, plan_from_acl, plan_from_poe, plan_from_drift,
    plan_from_routing, plan_remediations, merge_plans,
)
from netops_autopilot.engines.protocols import (
    parse_lldp, parse_cdp, parse_vtp, parse_stp, parse_dhcp_snooping,
    VtpMode, VtpStatus, LldpNeighbor, CdpNeighbor, StpReport,
)
from netops_autopilot.engines.root_cause import (
    analyze_link_down, analyze_connectivity_loss, analyze_routing_down,
    analyze_poe, Confidence, RootCauseAnalysis, _CATALOGUE,
)
from netops_autopilot.engines.distributed_discovery import (
    DistributedDiscovery, DiscoveryConfig, DiscoveryTarget,
    DiscoveryEvent, DistributedDiscoveryResult,
)
from netops_autopilot.engines.recommendations import (
    recommend, recommend_for_action,
    RecommendationCategory, Severity,
)


# ==================================================================
# P1 — Auto-remediation
# ==================================================================


def test_remediation_lowers_crc_port():
    plan = plan_from_health("d", [{
        "interface": "Gi0/1",
        "verdict": "critical",
        "crc": 200,
    }])
    assert plan.action_count == 1
    a = plan.actions[0]
    assert a.kind == ActionKind.LOWER_PORT_SPEED
    assert a.target_interface == "Gi0/1"
    assert "speed 100" in a.commands


def test_remediation_disables_fault_cable():
    plan = plan_from_health("d", [{
        "interface": "Gi0/2",
        "verdict": "critical",
        "crc": 0,
        "cable_diag": "fault",
    }])
    assert plan.actions[0].risk == RiskLevel.HIGH
    assert "shutdown" in plan.actions[0].commands


def test_remediation_resets_down_port():
    plan = plan_from_health("d", [{
        "interface": "Gi0/3",
        "verdict": "down",
    }])
    assert plan.actions[0].kind == ActionKind.RESET_INTERFACE


def test_remediation_removes_cold_acl():
    plan = plan_from_acl("d", [
        {"list_name": "100", "line_no": 30},
    ])
    assert plan.actions[0].kind == ActionKind.REMOVE_UNUSED_ACE
    assert "100" in plan.actions[0].commands[0]


def test_remediation_poe_disable_fault():
    plan = plan_from_poe("d", fault_ports=["Gi0/5"], over_budget=False)
    assert plan.actions[0].kind == ActionKind.DISABLE_FAULTY_POE_PORT
    assert plan.actions[0].risk == RiskLevel.HIGH


def test_remediation_drift_restore_from_golden():
    plan = plan_from_drift("d", [{"line": 1}], golden_text="...")
    assert plan.actions[0].kind == ActionKind.RESTORE_FROM_GOLDEN
    assert plan.actions[0].risk == RiskLevel.HIGH


def test_remediation_drift_accept_baseline():
    plan = plan_from_drift("d", [{"line": 1}])
    assert plan.actions[0].kind == ActionKind.ACCEPT_BASELINE
    assert plan.actions[0].risk == RiskLevel.LOW


def test_remediation_ospf_reset():
    plan = plan_from_routing("d", [
        {"protocol": "ospf", "neighbor": "10.0.0.2"},
    ])
    assert plan.actions[0].kind == ActionKind.RESTART_OSPF_PROCESS


def test_remediation_bgp_soft_reset():
    plan = plan_from_routing("d", [
        {"protocol": "bgp", "neighbor": "10.0.0.3"},
    ])
    assert plan.actions[0].kind == ActionKind.SOFT_RESET_BGP


def test_remediation_merged_overall_verdict():
    p1 = plan_from_health("d", [
        {"interface": "Gi0/1", "verdict": "critical", "crc": 200},
    ])
    p2 = plan_from_acl("d", [{"list_name": "100", "line_no": 20}])
    merged = merge_plans(p1, p2)
    assert merged.action_count == 2
    # MEDIUM is the highest here (no HIGH).
    assert merged.overall_verdict == "REVIEW_RECOMMENDED"


def test_remediation_top_level_planner():
    plan = plan_remediations(
        health=[{"interface": "Gi0/1", "verdict": "critical", "crc": 100}],
        cold_aces=[{"list_name": "100", "line_no": 10}],
        poe_faults=["Gi0/7"],
        down_neighbors=[{"protocol": "ospf", "neighbor": "1.1.1.1"}],
        drift_lines=[{"line": 1}],
        device_ref="d1",
    )
    assert plan.action_count >= 4


def test_remediation_renders_bilingual():
    plan = plan_remediations(
        health=[{"interface": "Gi0/1", "verdict": "critical", "crc": 100}],
    )
    en = plan.render("en")
    ar = plan.render("ar")
    assert "Remediation" in en
    assert "خطة" in ar


# ==================================================================
# P3 — Protocols
# ==================================================================


def test_lldp_parses_cisco_output():
    output = """
------------------------------------------------
Local Intf: Gi0/1
Chassis id: 0011.2233.4455
System Name: switch-01
System Description: Cisco IOS Software
Platform: cisco C9500-48Y4C
Port id: Gi0/2
Management Address: 10.0.0.1
------------------------------------------------
Local Intf: Gi0/2
Chassis id: aabb.ccdd.eeff
System Name: switch-02
"""
    nbrs = parse_lldp(output)
    assert len(nbrs) == 2
    assert nbrs[0].local_interface == "Gi0/1"
    assert nbrs[0].system_name == "switch-01"
    assert nbrs[0].mgmt_ip == "10.0.0.1"


def test_lldp_empty_returns_empty():
    assert parse_lldp("") == []


def test_cdp_parses_cisco_output():
    output = """
-------------------------
Device ID: switch-01
IP address: 10.0.0.1
Platform: cisco C9500-48Y4C,  Capabilities: Router Switch
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/2
Version: Cisco IOS Software
-------------------------
Device ID: switch-02
Platform: cisco C2960X-48TS-L
Interface: GigabitEthernet0/2,  Port ID (outgoing port): GigabitEthernet0/1
"""
    nbrs = parse_cdp(output)
    assert len(nbrs) == 2
    assert nbrs[0].device_id == "switch-01"
    assert nbrs[0].local_interface == "GigabitEthernet0/1"
    assert nbrs[0].mgmt_ip == "10.0.0.1"


def test_vtp_parses_cisco_output():
    output = """
VTP Version capable             : 1 to 3
VTP version running             : 2
VTP Domain Name                 : mydomain
VTP Operating Mode              : server
Configuration Revision          : 5
"""
    s = parse_vtp(output)
    assert s.vtp_domain == "mydomain"
    assert s.vtp_mode == VtpMode.SERVER
    assert s.vtp_revision == 5


def test_vtp_rogue_detected():
    s = VtpStatus(
        vtp_domain="x",
        vtp_mode=VtpMode.TRANSPARENT,
        vtp_revision=10,
    )
    assert s.is_rogue


def test_stp_parses_summary():
    output = """
VLAN0001     4096 0001.0001.0001   0   Gi0/1
VLAN0010     4096 0001.0001.0001   0   Gi0/2
VLAN0020     4096 0001.0001.0001   0   Gi0/3
"""
    r = parse_stp(output)
    assert len(r.instances) == 3
    assert r.instances[0].vlan_id == "0001"
    assert r.instances[0].root_bridge == "0001.0001.0001"


def test_dhcp_snoop_parses():
    status = """
Switch snooping is enabled
DHCP snooping violations: 3
Trusted interfaces: GigabitEthernet0/1
"""
    bindings = """
10.0.0.10  aabb.ccdd.eeff  10  Gi0/2  12345
10.0.0.11  aabb.ccdd.ee00  10  Gi0/3  12346
"""
    s = parse_dhcp_snooping(status, bindings)
    assert s.enabled is True
    assert s.violations == 3
    assert "GigabitEthernet0/1" in s.trusted_ports
    assert s.bindings_count == 2
    assert s.has_rogue_server


# ==================================================================
# P4 — Root-cause analysis
# ==================================================================


def test_root_cause_link_down_high_crc():
    a = analyze_link_down(interface="Gi0/1", crc_errors=200)
    cable = next(
        c for c in a.causes if c.pattern.id == "cable_fault"
    )
    assert cable.confidence == Confidence.HIGH


def test_root_cause_link_down_mtu():
    a = analyze_link_down(interface="Gi0/1", mtu_mismatch=True)
    cable = next(
        c for c in a.causes if c.pattern.id == "mtu_mismatch"
    )
    assert cable.confidence == Confidence.HIGH


def test_root_cause_routing_ospf_area():
    a = analyze_routing_down(
        peer="10.0.0.2", protocol="ospf",
        ospf_area_mismatch=True,
    )
    cause = next(
        c for c in a.causes if c.pattern.id == "ospf_area_mismatch"
    )
    assert cause.confidence == Confidence.HIGH


def test_root_cause_routing_bgp_as():
    a = analyze_routing_down(
        peer="10.0.0.2", protocol="bgp", bgp_as_mismatch=True,
    )
    cause = next(
        c for c in a.causes if c.pattern.id == "bgp_as_mismatch"
    )
    assert cause.confidence == Confidence.HIGH


def test_root_cause_acl_shadowing():
    a = analyze_connectivity_loss(
        src="A", dst="B", acl_shadowed=2,
    )
    cause = next(
        c for c in a.causes if c.pattern.id == "acl_shadowing"
    )
    assert cause.confidence == Confidence.HIGH


def test_root_cause_renders_both_languages():
    a = analyze_link_down(interface="Gi0/1", crc_errors=200)
    en = a.render("en")
    ar = a.render("ar")
    assert "Root-cause" in en
    assert "السبب" in ar


def test_root_cause_primary_highest_confidence():
    a = analyze_link_down(
        interface="Gi0/1", crc_errors=200, mtu_mismatch=True,
    )
    assert a.primary is not None
    assert a.primary.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_root_cause_poe_over_budget():
    a = analyze_poe(over_budget=True, utilization_pct=110.0)
    cause = next(
        c for c in a.causes if c.pattern.id == "power_budget"
    )
    assert cause.confidence == Confidence.HIGH


# ==================================================================
# P5 — Distributed discovery
# ==================================================================


def _make_target(ref: str) -> DiscoveryTarget:
    return DiscoveryTarget(
        seed_ref=ref,
        host=f"10.0.0.{ref[-1] or '1'}",
    )


def test_distributed_discovery_runs_in_parallel():
    async def fake_probe(t: DiscoveryTarget) -> DiscoveryEvent:
        await asyncio.sleep(0.05)
        return DiscoveryEvent(
            target=t, ok=True, device_ref=t.seed_ref, elapsed_s=0.05,
        )

    async def run():
        dd = DistributedDiscovery(DiscoveryConfig(max_concurrency=4))
        targets = [_make_target(f"d{i}") for i in range(8)]
        return await dd.run(targets, probe=fake_probe)

    result = asyncio.run(run())
    assert result.reachable_count == 8
    assert result.overall_verdict == "ALL_REACHABLE"


def test_distributed_discovery_retries_on_failure():
    attempts: dict[str, int] = {}

    async def flaky_probe(t: DiscoveryTarget) -> DiscoveryEvent:
        attempts[t.seed_ref] = attempts.get(t.seed_ref, 0) + 1
        if attempts[t.seed_ref] < 2:
            return DiscoveryEvent(
                target=t, ok=False, error="transient",
            )
        return DiscoveryEvent(
            target=t, ok=True, device_ref=t.seed_ref,
        )

    async def run():
        dd = DistributedDiscovery(DiscoveryConfig(
            max_concurrency=2, max_retries=2, retry_backoff_s=0.0,
        ))
        return await dd.run([_make_target("d1")], probe=flaky_probe)

    result = asyncio.run(run())
    assert result.reachable_count == 1
    # First event is the failure, second is the success
    assert any(e.ok for e in result.events)
    assert any(not e.ok for e in result.events)


def test_distributed_discovery_bounded_concurrency():
    concurrent = 0
    peak = 0

    async def slow_probe(t: DiscoveryTarget) -> DiscoveryEvent:
        nonlocal concurrent, peak
        concurrent += 1
        peak = max(peak, concurrent)
        await asyncio.sleep(0.05)
        concurrent -= 1
        return DiscoveryEvent(target=t, ok=True, device_ref=t.seed_ref)

    async def run():
        dd = DistributedDiscovery(DiscoveryConfig(max_concurrency=3))
        targets = [_make_target(f"d{i}") for i in range(10)]
        return await dd.run(targets, probe=slow_probe)

    asyncio.run(run())
    assert peak <= 3


def test_distributed_discovery_timeout_marks_unreachable():
    async def slow_probe(t: DiscoveryTarget) -> DiscoveryEvent:
        await asyncio.sleep(5.0)  # will be timed out
        return DiscoveryEvent(target=t, ok=True, device_ref=t.seed_ref)

    async def run():
        dd = DistributedDiscovery(DiscoveryConfig(
            per_host_timeout_s=0.05, max_retries=0,
        ))
        return await dd.run([_make_target("d1")], probe=slow_probe)

    result = asyncio.run(run())
    assert result.reachable_count == 0
    assert result.overall_verdict == "ALL_UNREACHABLE"


# ==================================================================
# P6 — Recommendations
# ==================================================================


def test_recommend_add_trunk_required_security():
    rep = recommend_for_action("add_trunk")
    bpdu = next(
        r for r in rep.recommendations
        if r.pattern.id == "stp-guard-before-trunk"
    )
    assert bpdu.pattern.severity == Severity.REQUIRED
    assert bpdu.pattern.category == RecommendationCategory.SECURITY


def test_recommend_initial_deploy():
    rep = recommend_for_action("initial_deploy")
    titles = {r.pattern.id for r in rep.recommendations}
    assert "ntp-on-everything" in titles
    assert "ssh-v2-only" in titles


def test_recommend_no_match_returns_empty():
    rep = recommend_for_action("no_such_action")
    assert rep.recommendations == []


def test_recommend_bgp_loopback():
    rep = recommend_for_action("add_bgp")
    rec = next(
        r for r in rep.recommendations
        if r.pattern.id == "l3-ibgp-loopback"
    )
    assert rec.pattern.severity == Severity.ADVISED


def test_recommend_renders_bilingual():
    rep = recommend_for_action("add_trunk")
    en = rep.render("en")
    ar = rep.render("ar")
    assert "Recommendations" in en
    assert "توصيات" in ar
