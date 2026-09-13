"""Neighbor parsers (D5-capstone): golden fixtures, typed failures.

The fixtures' LLDP/CDP/MNDP payloads are synthetic-representative until the
first lab capture lands (register OI-0131..0134 family; OI-0170, OI-0172) —
the CONTRACT tested here (anchored blocks, typed absence, never-guess
semantics) is vendor-shape and survives fixture replacement.
"""

import json
from pathlib import Path

from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir

from netops_autopilot.ledger.models import ParseStatus
from netops_autopilot.parsers.catalog import default_registry
from netops_autopilot.parsers.neighbor_parsers import ENTRY_KEYS, NEIGHBOR_CATALOG_BUILDERS

FIXTURES = simfabric_fixtures_dir()

CASES = (
    ("cisco_iosxe", "show_lldp_neighbors_detail"),
    ("cisco_iosxe", "show_cdp_neighbors_detail"),
    ("junos", "show_lldp_neighbors"),
    ("routeros", "ip_neighbor_print"),
    ("arubaos", "show_lldp_neighbors"),
    ("fortios", "get_system_lldp_neighbors"),
)


def _as_map(observations):
    return {o.field: (o.parse_status, o.value) for o in observations}


def test_all_neighbor_parsers_registered_in_catalog():
    registry = default_registry()
    for builder in NEIGHBOR_CATALOG_BUILDERS:
        parser = builder()
        assert registry.latest(parser.info.parser_id).info.parser_id == parser.info.parser_id


def test_entry_keys_fixed_set():
    assert ENTRY_KEYS == ("local_intf", "neighbor_id", "neighbor_intf",
                          "chassis_id", "mgmt_address", "platform", "protocol")


def test_golden_neighbor_tables():
    for rel_dir, name in CASES:
        raw = (FIXTURES / rel_dir / f"{name}.txt").read_bytes()
        expected = json.loads((FIXTURES / rel_dir / f"{name}.expected.json").read_text())
        parser = default_registry().latest(expected["parser_id"])
        assert parser.info.command_ref == expected["command"]
        obs = parser.parse(raw, raw_id=f"raw-{name}")
        got = _as_map(obs)
        for exp in expected["expected"]:
            status, value = got[exp["field"]]
            assert status.value == exp["parse_status"], f"{name}:{exp['field']}"
            assert value == exp["value"], f"{name}:{exp['field']}"


def test_golden_unifi_lldp_table():
    raw = (FIXTURES / "unifi" / "stat_device_lldp.json").read_bytes()
    expected = json.loads((FIXTURES / "unifi" / "stat_device_lldp.expected.json").read_text())
    parser = default_registry().latest(expected["parser_id"])
    obs = parser.parse(raw, raw_id="raw-unifi")
    got = _as_map(obs)
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status.value == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_garbage_input_is_missing_never_raised_never_guessed():
    """L03/L01: unrecognizable bytes ⇒ MISSING for every parser, no exception."""
    for builder in NEIGHBOR_CATALOG_BUILDERS:
        parser = builder()
        obs = parser.parse(b"\x00\xff not any console output \x07", raw_id="raw-garbage")
        got = _as_map(obs)
        table_fields = [f for f in got if f.startswith("neighbor_table_")]
        count_fields = [f for f in got if f.startswith("neighbor_count_")]
        assert len(table_fields) == len(count_fields) == 1, parser.info.parser_id
        assert got[table_fields[0]][0] is ParseStatus.MISSING, parser.info.parser_id
        assert got[count_fields[0]][0] is ParseStatus.MISSING, parser.info.parser_id


def test_positively_empty_table_is_ok_zero():
    """A header confirming zero neighbors is evidence of empty, not unknown."""
    parser = default_registry().latest("regex/junos_show_lldp_neighbors")
    obs = parser.parse(
        b"Local Interface    Parent Interface    Chassis Id          Port info          System Name\n",
        raw_id="raw-empty")
    got = _as_map(obs)
    assert got["neighbor_table_lldp"] == (ParseStatus.OK, [])
    assert got["neighbor_count_lldp"] == (ParseStatus.OK, 0)


def test_fixed_entry_key_set_in_every_emitted_row():
    for rel_dir, name in CASES + (("unifi", "stat_device_lldp"),):
        path = FIXTURES / rel_dir / (f"{name}.txt" if name != "stat_device_lldp" else f"{name}.json")
        registry = default_registry()
        parser_id = json.loads((FIXTURES / rel_dir / f"{name}.expected.json").read_text())["parser_id"]
        obs = registry.latest(parser_id).parse(path.read_bytes(), raw_id=f"raw-{name}")
        table = next(o.value for o in obs if o.field.startswith("neighbor_table_"))
        for row in table:
            assert tuple(row.keys()) == ENTRY_KEYS, f"{name}: row keys drifted"
