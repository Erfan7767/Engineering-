"""Phase X — a device that never advertised itself is still discovered.

Discovery read only CDP and LLDP. Both are courtesy protocols: a firewall with
LLDP disabled, a server, an access point, or a switch with the feature switched
off is invisible to them. The platform therefore reported a *complete* topology
that was missing equipment physically cabled into the network — the "ignoring
things" failure it is not allowed to have.

ARP joined to the MAC address table answers the question those protocols cannot:
which addresses are live, and on which port was each learned. The evidence is
strictly weaker than a bidirectional neighbour advertisement, so it is graded as
such and never laundered into a confirmed neighbour.
"""

from __future__ import annotations

from pathlib import Path

from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir

import pytest

from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.engines.discovery_crawl import (
    DeviceClass,
    DeviceResult,
    DeviceStatus,
    DiscoveryCrawlEngine,
)
from netops_autopilot.parsers.l2l3_inventory import (
    CiscoIosXeArpParser,
    CiscoIosXeMacAddressTableParser,
)
from tests.support.simfabric import SimFabricFactory, make_ledger_stack

FIXTURES = simfabric_fixtures_dir() / "cisco_iosxe"


# =================================================== 1. the parsers themselves
def test_arp_golden():
    obs = {o.field: o for o in CiscoIosXeArpParser().parse(
        (FIXTURES / "show_ip_arp.txt").read_bytes(), "raw-arp")}
    assert obs["arp_table"].parse_status.value == "OK"
    assert obs["arp_count"].value == 6
    first = obs["arp_table"].value[0]
    assert first == {
        "protocol": "Internet", "address": "10.240.0.1", "age_minutes": "0",
        "hardware_addr": "0011.2233.4455", "type": "ARPA",
        "interface": "GigabitEthernet1/0/1",
    }
    # an empty Age column is explicit absence, never ''
    unknown_age = [r for r in obs["arp_table"].value if r["address"] == "10.240.0.10"]
    assert unknown_age[0]["age_minutes"] == "-"


def test_mac_address_table_golden():
    obs = {o.field: o for o in CiscoIosXeMacAddressTableParser().parse(
        (FIXTURES / "show_mac_address_table.txt").read_bytes(), "raw-mac")}
    assert obs["mac_table"].parse_status.value == "OK"
    # 8 real rows: the two footer lines are furniture, not devices
    assert obs["mac_count"].value == 8
    assert all(r["mac_address"] for r in obs["mac_table"].value)


@pytest.mark.parametrize("parser,fixture", [
    (CiscoIosXeArpParser, "show_ip_arp.txt"),
    (CiscoIosXeMacAddressTableParser, "show_mac_address_table.txt"),
])
def test_no_header_is_missing_never_an_empty_table(parser, fixture):
    """Unreadable and empty are different facts and must not be conflated."""
    obs = {o.field: o for o in parser().parse(b"garbage\nnot a table\n", "raw")}
    assert all(o.parse_status.value == "MISSING" for o in obs.values())


def test_footer_prose_never_becomes_a_device_row():
    """Positional splitting is only safe because the key's shape is checked.

    `Number of permanent entries: 2` sits in the same columns as a real row and
    was being accepted as one, inventing a MAC out of prose.
    """
    obs = {o.field: o for o in CiscoIosXeMacAddressTableParser().parse(
        (FIXTURES / "show_mac_address_table.txt").read_bytes(), "raw")}
    for row in obs["mac_table"].value:
        mac = row["mac_address"]
        assert mac.count(".") == 2 and all(len(p) == 4 for p in mac.split(".")), mac


def test_prose_in_the_arp_columns_is_rejected():
    raw = (b"Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
           b"Internet  10.0.0.1                0   0011.2233.4455  ARPA   Gi0/1\n"
           b"This line is prose and must not be parsed as a device row at all\n")
    obs = {o.field: o for o in CiscoIosXeArpParser().parse(raw, "raw")}
    assert obs["arp_count"].value == 1


# ================================================= 2. the derivation, in unit
def _device(ref, arp=(), mac=(), inv=(), mgmt=()):
    device = DeviceResult(device_ref=ref, classification=DeviceClass.SEED,
                          status=DeviceStatus.COMPLETE, mgmt_addresses=tuple(mgmt))
    device.arp_table = tuple(arp)
    device.mac_table = tuple(mac)
    device.interface_table = tuple(inv)
    return device


ARP = [
    {"address": "10.0.0.1", "hardware_addr": "0011.2233.4455",
     "interface": "Gi1/0/1", "age_minutes": "0"},
    {"address": "10.0.0.77", "hardware_addr": "5566.7788.99aa",
     "interface": "Gi1/0/7", "age_minutes": "3"},
    {"address": "10.0.0.99", "hardware_addr": "abcd.ef01.2345",
     "interface": "Gi1/0/8", "age_minutes": "8"},
]
MAC = [
    {"vlan": "10", "mac_address": "0011.2233.4455", "type": "DYNAMIC", "ports": "Gi1/0/1"},
    {"vlan": "10", "mac_address": "5566.7788.99aa", "type": "DYNAMIC", "ports": "Gi1/0/7"},
    {"vlan": "20", "mac_address": "abcd.ef01.2345", "type": "DYNAMIC", "ports": "Gi1/0/24"},
]
INVENTORY = [
    {"port": "Gi1/0/1", "vlan": "trunk", "status": "connected"},
    {"port": "Gi1/0/7", "vlan": "10", "status": "connected"},
    {"port": "Gi1/0/24", "vlan": "trunk", "status": "connected"},
]


class _Refusing:
    def open(self, device_ref, hints):
        raise Failure(cls=FailureClass.BLOCKED,
                      causes=(f"NO_DEVICE_AT:{device_ref}",))


def _engine():
    return DiscoveryCrawlEngine.__new__(DiscoveryCrawlEngine)


def test_known_management_addresses_are_not_re_discovered():
    """The device's own address, and every address a neighbour advertised."""
    visited = {"seed-01": _device("seed-01", ARP, MAC, INVENTORY, mgmt=("10.0.0.1",))}
    ips = [c[0] for c in _engine()._l3_candidates(visited)]
    assert "10.0.0.1" not in ips
    assert ips == ["10.0.0.77", "10.0.0.99"]


def test_the_seed_own_address_is_excluded_via_neighbour_tables():
    """A seed carries no evidence about itself; its neighbours do.

    Without this the seed re-discovers its own address as an unknown endpoint.
    """
    visited = {"seed-01": _device("seed-01", ARP, MAC, INVENTORY)}
    tables = {"core-sw2": [{"neighbor_id": "SEED-01", "mgmt_address": "10.0.0.1",
                            "local_intf": "Gi0/1", "neighbor_intf": "Gi1/0/1",
                            "protocol": "LLDP"}]}
    ips = [c[0] for c in _engine()._l3_candidates(visited, tables)]
    assert "10.0.0.1" not in ips


def test_no_tables_means_no_invented_endpoints():
    """L01: absent evidence is never turned into a device."""
    engine = _engine()
    assert engine._l3_candidates({"s": _device("s")}) == []
    endpoints, links = engine._discover_via_l2l3(
        {"s": _device("s")}, session_factory=_Refusing(),
        allowlist_of=lambda f: None, max_devices=256, max_l3_probes=32)
    assert endpoints == [] and links == []


def test_a_mac_with_no_arp_entry_is_not_an_endpoint():
    """Only the JOIN is evidence; one table alone proves nothing addressable."""
    visited = {"s": _device("s", arp=(), mac=MAC, inv=INVENTORY)}
    assert _engine()._l3_candidates(visited) == []


# ============================================== 3. evidence grading is honest
def test_inferred_link_is_never_graded_as_a_confirmed_neighbour():
    engine = _engine()
    visited = {"seed-01": _device("seed-01", ARP, MAC, INVENTORY, mgmt=("10.0.0.1",))}
    _endpoints, links = engine._discover_via_l2l3(
        dict(visited), session_factory=_Refusing(), allowlist_of=lambda f: None,
        max_devices=256, max_l3_probes=32)
    by_port = {l.endpoint_a.interface or l.endpoint_b.interface: l for l in links}
    # learned on an ACCESS port: something is there, but adjacency is inferred
    assert by_port["Gi1/0/7"].fsm4_state == "INFERRED"
    # learned on a TRUNK: an unannounced switch may sit in between
    assert by_port["Gi1/0/24"].fsm4_state == "INTERMEDIATE_SUSPECTED"
    for link in links:
        assert link.fsm4_state not in ("DIRECT_NEIGHBOR_PROBABLE",
                                       "DIRECT_NEIGHBOR_CONFIRMED")
        assert link.protocols == ("ARP", "MAC_ADDRESS_TABLE")


def test_port_kind_comes_from_the_device_own_inventory():
    engine = _engine()
    device = _device("s", ARP, MAC, INVENTORY)
    assert engine._port_kind(device, "Gi1/0/1") == "TRUNK"
    assert engine._port_kind(device, "Gi1/0/7") == "ACCESS"
    assert engine._port_kind(device, "Gi1/0/99") == "UNKNOWN"   # not in inventory
    assert engine._port_kind(_device("s"), "Gi1/0/7") == "UNKNOWN"  # no inventory


def test_the_probe_budget_records_what_it_did_not_probe():
    """Nothing seen is silently dropped; the reason is carried."""
    engine = _engine()
    visited = {"seed-01": _device("seed-01", ARP, MAC, INVENTORY, mgmt=("10.0.0.1",))}
    endpoints, _links = engine._discover_via_l2l3(
        dict(visited), session_factory=_Refusing(), allowlist_of=lambda f: None,
        max_devices=256, max_l3_probes=0)
    assert len(endpoints) == 2
    assert all(not e.probed for e in endpoints)
    assert all("L3 probe budget 0 reached" in e.reason for e in endpoints)
    assert all("never silently dropped" in e.reason for e in endpoints)


# ================================================== 4. end to end on the fabric
def _run():
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y",
                                    intent="branch office with VoIP")),
        time_authority=time_auth)
    return engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                      mgmt_session_factory=fabric, port="SIM0", execute=False)


def test_a_device_with_lldp_disabled_is_discovered():
    """`fw-01` at 10.99.0.9 never advertises; CDP/LLDP alone cannot see it."""
    report = _run()
    refs = {d.device_ref for d in report.crawl.devices}
    assert "l3-10.99.0.9" in refs, refs
    endpoint = [e for e in report.crawl.l3_endpoints if e.ip == "10.99.0.9"]
    assert endpoint and endpoint[0].learned_on_port == "Gi1/0/9"
    device = next(d for d in report.crawl.devices if d.device_ref == "l3-10.99.0.9")
    assert device.classification is DeviceClass.NEIGHBOR_L3_EVIDENCE
    # honest about what the probe found: no session, so no identity was
    # invented. Either there is no identity record at all, or it carries no
    # vendor claim.
    assert device.status is DeviceStatus.UNREACHABLE
    assert device.identity is None or device.identity.vendor_family in (None, "UNKNOWN")


def test_the_l3_endpoint_is_announced_not_silently_configured():
    """Unreachable ⇒ outside the managed set, but present in the map and gaps."""
    report = _run()
    roles = {r.device_ref: r.role for r in report.design.roles}
    assert roles["l3-10.99.0.9"] == "UNMANAGED_NEIGHBOR"
    assert "l3-10.99.0.9" not in report.renders
    assert any(g.startswith("DEVICE_UNREACHABLE l3-10.99.0.9")
               for g in report.topology.gaps), report.topology.gaps
    assert any("LINK_EVIDENCE_BELOW_CONF LINK:l3-10.99.0.9" in g
               for g in report.topology.gaps), report.topology.gaps


def test_discovery_does_not_duplicate_devices_it_already_knows():
    """The three CDP/LLDP devices appear exactly once, at their own refs."""
    report = _run()
    refs = [d.device_ref for d in report.crawl.devices]
    assert len(refs) == len(set(refs))
    for known in ("seed-01", "core-sw2", "access-sw1"):
        assert known in refs
    # their addresses were excluded from the L3 pass, so no l3- alias for them
    assert not any(r in refs for r in ("l3-10.99.0.1", "l3-10.99.0.2", "l3-10.99.0.3"))
