"""Tests for Phase S — SNMP / NetConf / IPv6 / QoS / VPN / Multicast / Vault / Topology import / Config diff."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.snmp import (
    SnmpInterface, build_report, parse_snmpwalk, parse_uptime,
)
from netops_autopilot.engines.netconf import (
    NetConfOp, NetConfOperation, parse_netconf_reply,
    build_request, NetConfVerdict,
)
from netops_autopilot.engines.ipv6 import (
    parse_cisco_brief,
)
from netops_autopilot.engines.qos import (
    parse_policy_maps, DscpClass,
)
from netops_autopilot.engines.vpn import (
    parse_crypto_isakmp,
)
from netops_autopilot.engines.multicast import (
    parse_igmp_groups, parse_pim_neighbors,
)
from netops_autopilot.engines.vault import (
    Vault, DeviceCredentials,
)
from netops_autopilot.engines.topology_import import (
    parse_eve_ng_yaml, parse_netbox_json,
)
from netops_autopilot.engines.config_diff import (
    diff, DiffAction,
)


# ==================================================================
# S1 — SNMP
# ==================================================================


def test_snmp_parse_snmpwalk():
    text = """\
IF-MIB::ifInOctets.1 = Counter32: 1234567890
IF-MIB::ifOutOctets.1 = Counter32: 9876543210
SNMPv2-MIB::sysName.0 = STRING: edge-sw-01
"""
    out = parse_snmpwalk(text)
    assert "IF-MIB::ifInOctets.1" in out
    assert out["SNMPv2-MIB::sysName.0"] == "edge-sw-01"


def test_snmp_build_report():
    ifaces = [
        SnmpInterface(if_index=1, name="Gi0/1",
                      speed_bps=1_000_000_000, oper_status=1),
        SnmpInterface(if_index=2, name="Gi0/2",
                      speed_bps=10_000_000_000, oper_status=2),
    ]
    rep = build_report(
        target="10.0.0.1",
        sys_name="core-sw-01",
        sys_descr="Cisco IOS",
        sys_uptime_seconds=86400,
        interfaces=ifaces,
    )
    assert rep.interface_count == 2
    assert rep.up_count == 1
    assert rep.total_bandwidth_bps == 11_000_000_000


def test_snmp_parse_uptime():
    text = "197 uptime\n"
    assert parse_uptime(text) == 197


def test_snmp_empty_input():
    rep = build_report(
        target="", sys_name="", sys_descr="",
        sys_uptime_seconds=0, interfaces=[],
    )
    assert rep.interface_count == 0
    text = rep.render("en")
    assert "Interfaces: 0" in text


# ==================================================================
# S2 — NetConf
# ==================================================================


def test_netconf_build_request():
    req = build_request(
        target="10.0.0.1",
        operations=[
            NetConfOperation(
                op=NetConfOp.GET,
                filter_xpath="/interfaces",
            ),
        ],
    )
    assert req.target == "10.0.0.1"
    assert req.render("en").startswith("NetConf")


def test_netconf_parse_ok_reply():
    rep = parse_netconf_reply(
        1, "<rpc-reply><ok/></rpc-reply>",
    )
    assert rep.verdict == NetConfVerdict.OK
    assert rep.is_ok


def test_netconf_parse_error_reply():
    rep = parse_netconf_reply(
        1, "<rpc-reply><rpc-error><error-message>bad path</error-message></rpc-error></rpc-reply>",
    )
    assert rep.verdict == NetConfVerdict.RPC_ERROR
    assert "bad path" in rep.message


def test_netconf_lock_denied():
    rep = parse_netconf_reply(
        1, "<rpc-reply><rpc-error><error-message>lock-denied by other client</error-message></rpc-error></rpc-reply>",
    )
    assert rep.verdict == NetConfVerdict.LOCK_DENIED


# ==================================================================
# S3 — IPv6
# ==================================================================


def test_ipv6_parse_cisco_brief():
    text = """\
Interface              Status    Up Time    Address
GigabitEthernet0/0     up        12:30:14   2001:db8::1
GigabitEthernet0/1     up        12:30:14   fe80::1
GigabitEthernet0/2     down      --         --
"""
    rep = parse_cisco_brief("core-sw-01", text)
    assert rep.interface_count == 3
    assert rep.up_count == 2
    assert rep.dual_stack_count >= 1


def test_ipv6_empty():
    rep = parse_cisco_brief("core-sw-01", "")
    assert rep.interface_count == 0


# ==================================================================
# S4 — QoS
# ==================================================================


def test_qos_parse_policy_maps():
    text = """\
Policy Map QoS-VOICE
  Class VOICE
    dscp ef
    bandwidth 30
    priority
  Class DATA
    dscp af41
    bandwidth 50
Policy Map QoS-DATA
  Class DEFAULT
    dscp be
"""
    rep = parse_policy_maps("core-sw-01", text)
    assert rep.policy_count == 2
    assert rep.has_voice_policies == 1
    assert rep.policies[0].has_priority


def test_qos_empty():
    rep = parse_policy_maps("core-sw-01", "")
    assert rep.policy_count == 0


# ==================================================================
# S5 — IPSec VPN
# ==================================================================


def test_vpn_parse_crypto_isakmp():
    text = """\
peer 10.99.0.1 port 500
peer 10.99.0.2 port 500
"""
    rep = parse_crypto_isakmp("vpn-gw-01", text)
    assert rep.tunnel_count == 2
    # isakmp sa only shows phase1, not phase2.
    assert all(t.phase1_up for t in rep.tunnels)


def test_vpn_empty():
    rep = parse_crypto_isakmp("vpn-gw-01", "")
    assert rep.tunnel_count == 0


# ==================================================================
# S6 — Multicast
# ==================================================================


def test_multicast_parse_igmp_groups():
    text = """\
239.1.2.3  Gi0/1   00:01:30  10.0.0.10
239.1.2.4  Gi0/1   00:02:45  10.0.0.11
"""
    rep = parse_igmp_groups("core-sw-01", text)
    assert rep.igmp_count == 2
    assert rep.igmp_groups[0].uptime_seconds == 90


def test_multicast_parse_pim_neighbors():
    text = """\
10.99.0.1  Gi0/0  1d2h  100
10.99.0.2  Gi0/1  00:30:00  1
"""
    rep = parse_pim_neighbors("core-sw-01", text)
    assert rep.pim_count == 2
    assert rep.pim_neighbors[0].dr_priority == 100


# ==================================================================
# S7 — Credential vault
# ==================================================================


def test_vault_add_get_remove():
    v = Vault()
    c1 = DeviceCredentials(
        device_ref="core-sw-01", username="admin",
        password="secret", enable_password="enable",
    )
    c2 = DeviceCredentials(
        device_ref="edge-sw-01", username="admin",
        snmp_community="public",
    )
    v.add(c1)
    v.add(c2)
    assert v.device_count == 2
    assert v.get("core-sw-01") is c1
    assert v.remove("core-sw-01") is True
    assert v.device_count == 1


def test_vault_redact_no_leak():
    c = DeviceCredentials(
        device_ref="d1", username="admin", password="hunter2",
    )
    out = c.redact()
    assert "hunter2" not in out
    assert "***" in out


def test_vault_render_bilingual():
    v = Vault()
    v.add(DeviceCredentials(device_ref="d1", username="admin"))
    en = v.render("en")
    ar = v.render("ar")
    assert "Vault" in en
    assert "الخزنة" in ar


# ==================================================================
# S8 — Topology import (EVE-NG + NetBox)
# ==================================================================


def test_topology_import_eve_ng():
    text = """\
name: lab-1
nodes:
- name: R1
  type: router
  image: vios
- name: SW1
  type: switch
  image: vios-l2
connections:
  R1: SW1
  SW1: R2
"""
    topo = parse_eve_ng_yaml(text)
    assert topo.node_count == 2
    assert topo.edge_count == 2
    assert topo.nodes[0].image == "vios"


def test_topology_import_netbox():
    payload = """{
      "name": "dc-1",
      "devices": [
        {"name": "R1", "device_type": "router", "primary_ip": "10.0.0.1"},
        {"name": "R2", "device_type": "router", "primary_ip": "10.0.0.2"}
      ],
      "interfaces": [
        {"device": "R1", "name": "Gi0/0", "cable": {"peer_device": "R2"}}
      ]
    }"""
    topo = parse_netbox_json(payload)
    assert topo.node_count == 2
    assert topo.edge_count == 1
    assert topo.nodes[0].mgmt_ip == "10.0.0.1"


def test_topology_import_empty():
    assert parse_eve_ng_yaml("").node_count == 0
    assert parse_netbox_json("").node_count == 0


# ==================================================================
# S9 — Config diff
# ==================================================================


def test_config_diff_added_removed():
    a = "interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n"
    b = "interface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n"
    rep = diff(a=a, a_label="old", b=b, b_label="new")
    assert rep.has_changes
    assert rep.unchanged_count >= 1


def test_config_diff_no_changes():
    text = "interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n"
    rep = diff(a=text, a_label="x", b=text, b_label="y")
    assert not rep.has_changes
    assert rep.added_count == 0


def test_config_diff_render_bilingual():
    rep = diff(
        a="a\n", a_label="x",
        b="b\n", b_label="y",
    )
    en = rep.render("en")
    ar = rep.render("ar")
    assert "Diff" in en
    assert "الفرق" in ar
