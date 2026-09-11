"""Tests for Phase T — OSPF/ACL/PoE/Inventory/Cable/Backup/Compliance/NetDiff/Console."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.routing_protocol import (
    parse_cisco_ospf,
)
from netops_autopilot.engines.acl_analyzer import (
    parse_cisco_acl, AclAction,
)
from netops_autopilot.engines.poe_budget import (
    PowerBudgetReport, PoePoweredDevice, PoeClass,
)
from netops_autopilot.engines.inventory_items import (
    parse_cisco_inventory,
)
from netops_autopilot.engines.cable_plant import (
    parse_cable_plant,
)
from netops_autopilot.engines.backup_schedule import (
    BackupPolicy, build_schedule,
)
from netops_autopilot.engines.compliance_baseline import (
    get_pack, run_pack,
)
from netops_autopilot.engines.network_diff import (
    DeviceConfig, build_report,
)
from netops_autopilot.engines.console_server import (
    ConsoleServerConfig, build_inventory,
)


# ==================================================================
# T1 — OSPF routing protocol
# ==================================================================


def test_ospf_parse_minimal():
    text = """\
GigabitEthernet0/0 is up, line protocol is up
  Internet Address 10.0.0.1/24, Area 0
  Cost: 1
  Timer intervals configured, Hello 10, Dead 40
  Network type BROADCAST
"""
    rep = parse_cisco_ospf("core-sw-01", text)
    assert rep.interface_count == 1
    assert rep.mis_tuned == []


def test_ospf_parse_mis_tuned():
    text = """\
GigabitEthernet0/0 is up, line protocol is up
  Internet Address 10.0.0.1/24, Area 0
  Cost: 1
  Timer intervals configured, Hello 30, Dead 120
  Network type BROADCAST
"""
    rep = parse_cisco_ospf("core-sw-01", text)
    assert rep.interface_count == 1
    assert len(rep.mis_tuned) == 1


def test_ospf_empty():
    rep = parse_cisco_ospf("core-sw-01", "")
    assert rep.interface_count == 0


# ==================================================================
# T2 — ACL analyzer
# ==================================================================


def test_acl_parse_basic():
    text = """\
10 permit tcp 10.0.0.0 0.255.255.255 any eq 80
20 permit tcp 10.0.0.0 0.255.255.255 any eq 443
30 deny ip any any
"""
    rep = parse_cisco_acl("WEB-FILTER", text)
    assert rep.rule_count == 3
    assert rep.permit_count == 2
    assert rep.deny_count == 1


def test_acl_duplicate_finding():
    text = """\
10 permit tcp any any eq 80
20 permit tcp any any eq 80
"""
    rep = parse_cisco_acl("DUP", text)
    assert rep.finding_count >= 1
    assert any(
        f.kind == "duplicate" for f in rep.findings
    )


def test_acl_any_any_at_end():
    text = """\
10 permit tcp any any eq 80
20 deny ip any any
"""
    rep = parse_cisco_acl("ANY-ANY", text)
    assert any(
        f.kind == "any_any_at_end" for f in rep.findings
    )


# ==================================================================
# T3 — PoE power budget
# ==================================================================


def test_poe_under_budget():
    devs = [
        PoePoweredDevice(
            port="Gi0/1", device_id="ap-01",
            poe_class=PoeClass.CLASS_3,
        ),
        PoePoweredDevice(
            port="Gi0/2", device_id="phone-01",
            poe_class=PoeClass.CLASS_2,
        ),
    ]
    rep = PowerBudgetReport(
        device="core-sw-01",
        total_budget_watts=370.0,
        devices=devs,
    )
    assert rep.allocated_watts == pytest_approx(22.4)
    assert not rep.is_over_budget


def test_poe_over_budget():
    devs = [
        PoePoweredDevice(
            port="Gi0/1", device_id="ap-01",
            poe_class=PoeClass.CLASS_4,
        ) for _ in range(20)
    ]
    rep = PowerBudgetReport(
        device="edge-sw-01",
        total_budget_watts=370.0,
        devices=devs,
    )
    assert rep.is_over_budget


def test_poe_render_bilingual():
    rep = PowerBudgetReport(
        device="x", total_budget_watts=100.0,
    )
    en = rep.render("en")
    ar = rep.render("ar")
    assert "PoE" in en
    assert "PoE" in ar


def pytest_approx(val: float, tol: float = 0.1) -> float:
    return val  # alias used in the test


# ==================================================================
# T4 — Hardware inventory
# ==================================================================


def test_inventory_parse_cisco():
    text = """\
NAME: "Chassis", DESCR: "Cisco ISR4451 Chassis"
PID: ISR4451/K9         , VID: V05 , SN: FOC12345678
NAME: "module 0", DESCR: "ISR4451 Built-In NIM controller"
"""
    rep = parse_cisco_inventory("core-router-01", text)
    assert rep.item_count == 2
    assert rep.items[0].pid == "ISR4451/K9"


def test_inventory_empty():
    rep = parse_cisco_inventory("x", "")
    assert rep.item_count == 0


# ==================================================================
# T5 — Cable plant
# ==================================================================


def test_cable_plant_parse_lines():
    text = """\
A1:1 -> floor1-desk1 cat6 30m
A1:2 -> floor1-desk2 cat6 35m
B1:1 -> IDF-1-sm-fc1 sm 50m
"""
    rep = parse_cable_plant("site-A", text)
    assert rep.record_count == 3
    assert rep.fiber_count == 1
    assert rep.total_length_meters == 115.0


def test_cable_plant_empty():
    rep = parse_cable_plant("x", "")
    assert rep.record_count == 0


# ==================================================================
# T6 — Backup schedule
# ==================================================================


def test_backup_schedule_returns_events():
    from datetime import datetime
    p = BackupPolicy(name="daily")
    rep = build_schedule(
        p,
        start=datetime(2026, 1, 1, 0, 0, 0),
        horizon_days=40,
    )
    assert rep.event_count > 0
    # At least one daily + one weekly + one monthly.
    kinds = {e.kind for e in rep.events}
    assert "daily" in kinds


def test_backup_schedule_render_bilingual():
    p = BackupPolicy(name="x")
    from datetime import datetime
    rep = build_schedule(
        p,
        start=datetime(2026, 1, 1, 0, 0, 0),
        horizon_days=10,
    )
    en = rep.render("en")
    ar = rep.render("ar")
    assert "Backup" in en
    assert "النسخ" in ar


# ==================================================================
# T7 — Compliance baseline
# ==================================================================


def test_compliance_cis_pass():
    pack = get_pack("cis")
    config = (
        "service password-encryption\n"
        "aaa new-model\n"
    )
    rep = run_pack(pack, config)
    # CIS-003 expects no telnet — vacuous pass for this config.
    assert rep.pass_count >= 2


def test_compliance_pci_fail():
    pack = get_pack("pci")
    config = "transport input telnet\n"
    rep = run_pack(pack, config)
    assert rep.fail_count >= 1
    assert rep.overall_verdict in ("FAIL", "FAIL_CRITICAL")


def test_compliance_pci_critical_fail():
    pack = get_pack("pci")
    config = "transport input telnet\n"  # PCI-002 critical
    rep = run_pack(pack, config)
    assert rep.overall_verdict == "FAIL_CRITICAL"


# ==================================================================
# T8 — Network-wide diff
# ==================================================================


def test_network_diff_identical():
    config = "interface Gi0/1\n ip address 10.0.0.1\n"
    devs = [
        DeviceConfig(device_ref="sw1", config=config),
        DeviceConfig(device_ref="sw2", config=config),
    ]
    rep = build_report(devs)
    assert rep.device_count == 2
    assert len(rep.identical_pairs) == 1
    assert rep.divergent_pairs == []


def test_network_diff_divergent():
    devs = [
        DeviceConfig(
            device_ref="sw1",
            config="interface Gi0/1\n ip address 10.0.0.1\n",
        ),
        DeviceConfig(
            device_ref="sw2",
            config="interface Gi0/1\n ip address 10.0.0.2\n",
        ),
    ]
    rep = build_report(devs)
    assert len(rep.divergent_pairs) == 1


# ==================================================================
# T9 — Console server
# ==================================================================


def test_console_server_inventory():
    cs = ConsoleServerConfig(host="console-01.lab.local")
    inv = build_inventory(cs, ["core-sw-01", "edge-sw-01"])
    assert inv.path_count == 2
    assert inv.paths[0].host == "console-01.lab.local"
    assert inv.paths[0].port == 2000
    assert inv.paths[1].port == 2001


def test_console_server_max_ports():
    cs = ConsoleServerConfig(host="x", max_ports=2)
    inv = build_inventory(cs, ["a", "b", "c"])
    assert inv.path_count == 2


def test_console_server_render_bilingual():
    cs = ConsoleServerConfig(host="x")
    inv = build_inventory(cs, ["a"])
    en = inv.render("en")
    ar = inv.render("ar")
    assert "Console" in en
    assert "وحدة" in ar
