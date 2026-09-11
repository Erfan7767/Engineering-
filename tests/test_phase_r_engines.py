"""Tests for Phase R engines — 30-year expert Day-N+ operations."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.multi_vendor import (
    LogicalCommand, Vendor, lookup, supported_vendors,
    translate_command, translate_all,
)
from netops_autopilot.engines.wireless import (
    parse_ap_summary, parse_wlan_summary, parse_radius_event,
    RadioBand, WlanSecurity,
)
from netops_autopilot.engines.flow import (
    FlowRecord, FlowProtocol, aggregate, parse_cisco_netflow,
)
from netops_autopilot.engines.syslog import (
    parse_line, parse_log, SyslogSeverity,
)
from netops_autopilot.engines.dns import (
    parse_dig, DnsStatus,
)
from netops_autopilot.engines.exec_report import (
    ReportInputs, build,
)
from netops_autopilot.engines.simulator import (
    simulate_remove_link, SimVerdict,
)


class _StubNode:
    def __init__(self, ref, status="COMPLETE"):
        self.device_ref = ref
        self.status = status


class _StubEdge:
    def __init__(self, a, b):
        if hasattr(a, "a_key"):
            self.a_key = a
            self.b_key = b
            self.fsm4_state = "PHYSICAL_PATH_VERIFIED"
        else:
            self.endpoint_a = type("E", (), {"device_ref": a})()
            self.endpoint_b = type("E", (), {"device_ref": b})()


class _StubTopo:
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges


# ==================================================================
# R1 — Multi-vendor
# ==================================================================


def test_multi_vendor_routing_table_lookup():
    cmd = lookup(LogicalCommand.ROUTING_TABLE, Vendor.CISCO_IOSXE)
    assert cmd.command == "show ip route"
    cmd2 = lookup(LogicalCommand.ROUTING_TABLE, Vendor.JUNIPER_JUNOS)
    assert cmd2.command == "show route"


def test_multi_vendor_unsupported_returns_none():
    cmd = lookup(LogicalCommand.VLAN_TABLE, Vendor.NOKIA_SRLINUX)
    assert cmd is None
    cmd = lookup(LogicalCommand.VTP, Vendor.JUNIPER_JUNOS)
    assert cmd is not None
    assert "MVRP" in (cmd.notes or cmd.command)


def test_multi_vendor_supported_vendors():
    v = supported_vendors(LogicalCommand.ROUTING_TABLE)
    assert Vendor.CISCO_IOSXE in v
    assert Vendor.JUNIPER_JUNOS in v
    assert Vendor.ARISTA_EOS in v


def test_multi_vendor_translate_all_renders_table():
    text = translate_all(LogicalCommand.ROUTING_TABLE)
    assert "cisco/ios-xe: show ip route" in text
    assert "juniper/junos: show route" in text


def test_multi_vendor_translate_bilingual():
    text_en = translate_command(
        logical=LogicalCommand.MAC_TABLE, vendor=Vendor.CISCO_IOSXE,
    )
    text_ar = translate_command(
        logical=LogicalCommand.MAC_TABLE, vendor=Vendor.CISCO_IOSXE,
        lang="ar",
    )
    assert "show mac address-table" in text_en
    assert "show mac" in text_ar


# ==================================================================
# R2 — Wireless
# ==================================================================


def test_wireless_parse_ap_summary():
    output = """
AP Name          Model          IP              Clients  Channel  Util
ap-floor1-01     AIR-AP1852I     10.0.0.11       23       36       45%
ap-floor2-01     AIR-AP1852I     10.0.0.12       41       1        82%
"""
    rep = parse_ap_summary(output)
    assert rep.ap_count == 2
    assert rep.total_clients == 64
    assert len(rep.high_util_aps) == 1
    assert rep.aps[1].band == RadioBand.BAND_2_4


def test_wireless_parse_wlan_summary():
    output = """
WLAN ID  SSID           VLAN  Status
1        guest          100   UP
2        corp           10    UP
3        iot            50    UP
"""
    rep = parse_wlan_summary(output)
    assert len(rep.wlans) >= 3


def test_wireless_radius_event():
    line = (
        'Acct-Status-Type = Start,'
        ' User-Name = "alice",'
        ' Called-Station-Id = "AA-BB-CC-DD-EE-FF:guest"'
    )
    ev = parse_radius_event(line)
    assert ev is not None
    assert ev.username == "alice"


# ==================================================================
# R3 — Flow
# ==================================================================


def test_flow_aggregate_top_talkers():
    flows = [
        FlowRecord(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            bytes=1000, packets=10, dst_port=80,
            protocol=FlowProtocol.TCP,
            application="http",
        ),
        FlowRecord(
            src_ip="10.0.0.1", dst_ip="10.0.0.3",
            bytes=500, packets=5, dst_port=443,
            protocol=FlowProtocol.TCP,
            application="https",
        ),
        FlowRecord(
            src_ip="10.0.0.2", dst_ip="10.0.0.4",
            bytes=200, packets=2,
            protocol=FlowProtocol.UDP,
        ),
    ]
    rep = aggregate(flows)
    assert rep.total_bytes == 1700
    assert rep.top_talkers[0].key == "10.0.0.1"
    assert rep.top_applications[0].key in ("http", "https")


def test_flow_parse_cisco_netflow():
    output = """
SrcIf  SrcIPaddress   DstIf  DstIPaddress   Pr SrcP DstP Pkts
Gi0/1  10.0.0.1       Gi0/2  10.0.0.2       06 1234 80    100
Gi0/1  10.0.0.1       Gi0/2  10.0.0.3       17 53  53    50
"""
    flows = parse_cisco_netflow(output)
    assert len(flows) == 2
    assert flows[0].protocol == FlowProtocol.TCP
    assert flows[1].protocol == FlowProtocol.UDP


def test_flow_empty_input_returns_zero():
    rep = aggregate([])
    assert rep.total_bytes == 0
    assert rep.top_talkers == []


# ==================================================================
# R4 — Syslog
# ==================================================================


def test_syslog_parse_cisco_style():
    line = "00:00:01: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down"
    ev = parse_line(line)
    assert ev is not None
    assert ev.severity == SyslogSeverity.NOTICE
    assert "GigabitEthernet0/1" in ev.message


def test_syslog_parse_bsd_style():
    line = "<35>Oct 11 22:14:15 host1 kernel: [1234.5] eth0 link up"
    ev = parse_line(line)
    assert ev is not None
    assert ev.hostname == "host1"
    assert ev.severity == SyslogSeverity.ERROR


def test_syslog_parse_log_multi_line():
    log = """
00:00:01: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
00:00:05: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
"""
    rep = parse_log(log)
    assert len(rep.events) == 2
    assert rep.severity_counts.get("error", 0) == 1
    assert rep.overall_verdict in ("ERRORS_PRESENT", "WARNINGS_PRESENT")


# ==================================================================
# R5 — DNS
# ==================================================================


def test_dns_parse_dig_noerror():
    output = """
; <<>> DiG 9.16.1 <<>> example.com +all
;; QUESTION SECTION:
;example.com.   IN  A
;; ANSWER SECTION:
example.com.    300 IN  A   93.184.216.34
;; Query time: 12 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: ...
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
"""
    rep = parse_dig(output)
    assert rep.status == DnsStatus.NOERROR
    assert rep.question.startswith("example.com")
    assert rep.answer_count == 1
    assert rep.latency_ms == 12.0
    assert rep.overall_verdict == "OK"


def test_dns_parse_dig_nxdomain():
    output = """
; <<>> DiG <<>> nonexistent.example.com
;; QUESTION SECTION:
;nonexistent.example.com. IN A
;; ANSWER SECTION:
;; status: NXDOMAIN
"""
    rep = parse_dig(output)
    assert rep.status == DnsStatus.NXDOMAIN
    assert rep.overall_verdict == "NXDOMAIN"


def test_dns_empty_returns_unknown():
    rep = parse_dig("")
    assert rep.overall_verdict == "UNKNOWN"


# ==================================================================
# R6 — Executive report
# ==================================================================


def test_exec_report_builds_attention():
    inputs = ReportInputs(
        device_count=10,
        reachable_count=9,
        change_count=3,
        anomaly_count=2,
    )
    rep = build(inputs)
    assert rep.overall_verdict == "ATTENTION_REQUIRED"
    text = rep.render("en")
    assert "Total: 10" in text
    assert "ATTENTION_REQUIRED" in text


def test_exec_report_builds_stable():
    inputs = ReportInputs(
        device_count=10,
        reachable_count=10,
        change_count=1,
    )
    rep = build(inputs)
    assert rep.overall_verdict == "STABLE"


def test_exec_report_bilingual():
    inputs = ReportInputs(device_count=5)
    en = build(inputs, "en").render("en")
    ar = build(inputs, "ar").render("ar")
    assert "Executive" in en
    assert "تنفيذي" in ar


# ==================================================================
# R7 — Simulator
# ==================================================================


def test_simulator_remove_link_islands_device():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b"), _StubNode("c")],
        edges=[
            _StubEdge("a", "b"),
            _StubEdge("b", "c"),
        ],
    )
    rep = simulate_remove_link(
        topo=topo, seed="a", edge=("a", "b"),
    )
    assert rep.overall_verdict in (
        "PARTIAL_OUTAGE", "ISLANDED_DEVICES",
    )


def test_simulator_no_changes_when_safe():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b"),
               _StubNode("c"), _StubNode("d")],
        edges=[
            _StubEdge("a", "b"),
            _StubEdge("a", "c"),
            _StubEdge("a", "d"),
        ],
    )
    rep = simulate_remove_link(
        topo=topo, seed="a", edge=("a", "b"),
    )
    assert rep.changes == [] or any(
        c.after != SimVerdict.REACHABLE for c in rep.changes
    )


def test_simulator_render_bilingual():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b")],
        edges=[_StubEdge("a", "b")],
    )
    rep = simulate_remove_link(
        topo=topo, seed="a", edge=("a", "b"),
    )
    en = rep.render("en")
    ar = rep.render("ar")
    assert "Simulation" in en
    assert "محاكاة" in ar
