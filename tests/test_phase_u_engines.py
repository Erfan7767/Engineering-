"""Tests for Phase U — DNS zone / DHCPv6 / AAA / STP guard / Port security / Chassis / DDoS / RPKI / NTP."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.dns_zone import parse_zone_file
from netops_autopilot.engines.dhcpv6 import parse_ipv6_nd
from netops_autopilot.engines.aaa import parse_cisco_aaa
from netops_autopilot.engines.spanning_tree import parse_stp_interfaces
from netops_autopilot.engines.port_security import parse_port_security
from netops_autopilot.engines.chassis import parse_stack, parse_modules
from netops_autopilot.engines.ddos_detect import detect as detect_ddos
from netops_autopilot.engines.flow import FlowRecord, FlowProtocol
from netops_autopilot.engines.rpki import (
    RpkiValidation, RpkiState, evaluate,
)
from netops_autopilot.engines.ntp import parse_cisco_ntp


# ==================================================================
# U1 — DNS zone transfer audit
# ==================================================================


def test_dns_zone_parse_basic():
    text = """\
@ 3600 IN NS ns1.example.com.
@ 3600 IN A  192.0.2.1
www 3600 IN A 192.0.2.10
"""
    rep = parse_zone_file("example.com", text)
    assert rep.record_count == 3


def test_dns_zone_find_any_record():
    text = """\
@ 3600 IN ANY 0.0.0.0/0
"""
    rep = parse_zone_file("example.com", text)
    assert rep.any_count == 1
    assert rep.finding_count >= 1


def test_dns_zone_find_open_axfr():
    text = """\
allow-transfer { any; };
"""
    rep = parse_zone_file("example.com", text)
    assert any(
        f.kind == "open_axfr" for f in rep.findings
    )


# ==================================================================
# U2 — DHCPv6 / SLAAC
# ==================================================================


def test_dhcpv6_parse_slaac_only():
    text = """\
2001:db8::1 Gi0/0 valid 3600s preferred 1800s
"""
    rep = parse_ipv6_nd("core-sw-01", text)
    assert rep.slaac_count == 1
    assert rep.dhcpv6_count == 0


def test_dhcpv6_parse_stateful():
    text = """\
Client: aabbccdd IAID: 1 Address: 2001:db8::100 lifetime 7200
"""
    rep = parse_ipv6_nd("core-sw-01", text)
    assert rep.dhcpv6_count == 1


# ==================================================================
# U3 — AAA / TACACS+
# ==================================================================


def test_aaa_parse_with_tacacs():
    text = """\
10.99.0.10 { 49 cisco 5 }
aaa new-model
aaa authentication login default group tacacs+ local
"""
    rep = parse_cisco_aaa("core-sw-01", text)
    assert rep.server_count == 1
    assert rep.aaa_new_model is True
    assert rep.finding_count == 0


def test_aaa_finding_no_tacacs():
    text = "aaa new-model\n"
    rep = parse_cisco_aaa("core-sw-01", text)
    assert any(f.kind == "no_tacacs" for f in rep.findings)


# ==================================================================
# U4 — Spanning-tree BPDU/root guard
# ==================================================================


def test_stp_find_no_bpdu_guard():
    text = """\
Gi0/1 Desg Edge disabled disabled disabled
Gi0/2 Desg Network enabled disabled disabled
"""
    rep = parse_stp_interfaces("core-sw-01", text)
    assert rep.interface_count == 2
    assert any(
        f.kind == "no_bpdu_guard" for f in rep.findings
    )


def test_stp_find_no_root_guard():
    text = """\
Gi0/2 Desg Network enabled disabled disabled
"""
    rep = parse_stp_interfaces("core-sw-01", text)
    assert any(
        f.kind == "no_root_guard" for f in rep.findings
    )


# ==================================================================
# U5 — Port security / 802.1X
# ==================================================================


def test_port_security_parse():
    text = """\
Gi0/1 enabled 2 1 shutdown 300
Gi0/2 enabled 1 5 protect 300
"""
    rep = parse_port_security("edge-sw-01", text)
    assert rep.port_count == 2
    assert rep.enabled_count == 2
    # Gi0/2 has 5 > 1 = over limit
    assert len(rep.over_limit) == 1


# ==================================================================
# U6 — Chassis / stack
# ==================================================================


def test_stack_parse():
    text = """\
1 Active aa:bb:cc:dd:ee:01 Ready 15
2 Standby aa:bb:cc:dd:ee:02 Ready 10
3 Member aa:bb:cc:dd:ee:03 Ready 5
"""
    rep = parse_stack("stack-sw-01", text)
    assert rep.stack_size == 3
    assert rep.active_member is not None


def test_modules_parse_with_faulty():
    text = """\
1 48-port GIC1234567 ok 48
2 Supervisor SUP1234567 faulty 0
"""
    rep = parse_modules("modular-sw-01", text)
    assert len(rep.modules) == 2
    assert len(rep.faulty_modules) == 1


# ==================================================================
# U7 — DDoS detection
# ==================================================================


def test_ddos_detect_udp_flood():
    flows = [
        FlowRecord(
            src_ip="10.0.0.100", dst_ip="10.0.0.1",
            bytes=100, packets=500,
            protocol=FlowProtocol.UDP,
        ),
        FlowRecord(
            src_ip="10.0.0.100", dst_ip="10.0.0.1",
            bytes=100, packets=500,
            protocol=FlowProtocol.UDP,
        ),
    ]
    rep = detect_ddos(flows, syn_threshold=1000)
    assert rep.signal_count >= 1


def test_ddos_detect_no_signal_normal():
    flows = [
        FlowRecord(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            bytes=1000, packets=10,
            protocol=FlowProtocol.TCP,
        ),
    ]
    rep = detect_ddos(flows)
    assert rep.signal_count == 0


# ==================================================================
# U8 — RPKI / ROA
# ==================================================================


def test_rpki_evaluate_mixed():
    vals = [
        RpkiValidation(
            prefix="10.0.0.0/8", origin_asn=65001,
            state=RpkiState.VALID,
        ),
        RpkiValidation(
            prefix="172.16.0.0/12", origin_asn=65002,
            state=RpkiState.INVALID,
        ),
        RpkiValidation(
            prefix="192.168.0.0/16", origin_asn=65003,
            state=RpkiState.NOT_FOUND,
        ),
    ]
    rep = evaluate(vals)
    assert rep.valid_count == 1
    assert rep.invalid_count == 1
    assert rep.not_found_count == 1


def test_rpki_render_bilingual():
    rep = evaluate([])
    en = rep.render("en")
    ar = rep.render("ar")
    assert "RPKI" in en
    assert "RPKI" in ar


# ==================================================================
# U9 — NTP
# ==================================================================


def test_ntp_parse_minimal():
    text = """\
*10.99.0.1 .GPS. 1 100 64 377 1.234 0.567 0.890
"""
    rep = parse_cisco_ntp("core-sw-01", text)
    assert rep.peer_count == 1
    assert rep.peers[0].is_synchronized is True


def test_ntp_find_high_skew():
    text = """\
*10.99.0.1 .GPS. 1 100 64 377 1.234 250.0 0.890
"""
    rep = parse_cisco_ntp("core-sw-01", text)
    assert len(rep.high_skew) == 1


def test_ntp_render_bilingual():
    rep = parse_cisco_ntp("x", "")
    en = rep.render("en")
    ar = rep.render("ar")
    assert "NTP" in en
    assert "NTP" in ar
