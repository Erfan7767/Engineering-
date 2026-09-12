"""Golden fixtures for the four remaining v1 vendors + catalog + negative paths."""

import json
from pathlib import Path

import pytest

from netops_autopilot.ledger.models import ParseStatus
from netops_autopilot.parsers.catalog import CATALOG_BUILDERS, default_registry
from netops_autopilot.parsers.vendor_parsers import (
    UnifiDeviceJsonParser,
    arubaos_show_version,
    fortios_get_system_status,
    junos_show_version,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "golden"

CASES = (
    ("junos", "show_version", junos_show_version, "show_version.txt"),
    ("fortios", "get_system_status", fortios_get_system_status, "get_system_status.txt"),
    ("arubaos", "show_version", arubaos_show_version, "show_version.txt"),
)


@pytest.mark.parametrize("rel_dir,name,builder,raw_file", CASES)
def test_golden_vendor_fixture(rel_dir, name, builder, raw_file):
    raw = (FIXTURES / rel_dir / raw_file).read_bytes()
    expected = json.loads((FIXTURES / rel_dir / f"{name}.expected.json").read_text())
    parser = builder()
    assert parser.info.parser_id == expected["parser_id"]
    got = {o.field: (o.parse_status, o.value) for o in parser.parse(raw, raw_id="raw-g")}
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status.value == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_golden_unifi_stat_device():
    raw = (FIXTURES / "unifi" / "stat_device.json").read_bytes()
    expected = json.loads((FIXTURES / "unifi" / "stat_device.expected.json").read_text())
    parser = UnifiDeviceJsonParser()
    got = {o.field: (o.parse_status, o.value) for o in parser.parse(raw, raw_id="raw-u")}
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status.value == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_unifi_error_envelope_is_parse_failed():
    parser = UnifiDeviceJsonParser()
    bad_envelope = json.dumps({"meta": {"rc": "error"}, "data": []}).encode()
    obs = parser.parse(bad_envelope, raw_id="raw-x")
    assert len(obs) == 1 and obs[0].parse_status is ParseStatus.PARSE_FAILED
    assert obs[0].field == "_envelope"


def test_unifi_garbage_is_parse_failed():
    parser = UnifiDeviceJsonParser()
    obs = parser.parse(b"\xff\xfe{not json", raw_id="raw-x")
    assert obs[0].parse_status is ParseStatus.PARSE_FAILED and obs[0].field == "_payload"


def test_unifi_missing_device_fields_are_missing():
    parser = UnifiDeviceJsonParser()
    payload = json.dumps({"meta": {"rc": "ok"}, "data": [{"model": "U6-LR"}]}).encode()
    got = {o.field: o.parse_status for o in parser.parse(payload, raw_id="raw-x")}
    assert got["device[0].model"] is ParseStatus.OK
    assert got["device[0].serial"] is ParseStatus.MISSING
    assert got["device[0].ip"] is ParseStatus.MISSING


def test_junos_missing_fields_typed():
    parser = junos_show_version()
    obs = parser.parse(b"Hostname: only-host\n", raw_id="raw-j")
    got = {o.field: o.parse_status for o in obs}
    assert got["hostname"] is ParseStatus.OK
    assert got["model"] is ParseStatus.MISSING
    assert got["serial"] is ParseStatus.MISSING
    assert got["junos_version"] is ParseStatus.MISSING


def test_catalog_registers_all_v1_parsers_with_unique_ids():
    registry = default_registry()
    ids = [builder().info.parser_id for builder in CATALOG_BUILDERS]
    # 6 identity parsers (D1) + 7 neighbor parsers (D5-capstone OI-0170)
    # + 1 interface-inventory parser (Phase W: the port evidence the Design
    #   Engine needs to assign end-user access ports)
    # + 2 L2/L3 inventory parsers (Phase X: ARP and the MAC address table, so a
    #   device with CDP/LLDP disabled is still discovered instead of ignored).
    assert len(ids) == 16 and len(set(ids)) == len(ids)
    assert "regex/cisco_iosxe_show_interfaces_status" in ids
    assert "regex/cisco_iosxe_show_ip_arp" in ids
    assert "regex/cisco_iosxe_show_mac_address_table" in ids
    for parser_id in ids:
        assert registry.latest(parser_id).info.parser_id == parser_id
    families = {builder().info.vendor_family for builder in CATALOG_BUILDERS}
    assert families == {
        "mikrotik/routeros", "cisco/ios-xe", "juniper/junos",
        "fortinet/fortios", "aruba/arubaos", "ubiquiti/unifi",
    }
