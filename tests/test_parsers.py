"""E03 Parsers: golden fixtures per vendor, typed failures, registry."""

import json
from pathlib import Path

from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir

import pytest

from netops_autopilot.ledger.models import ParseStatus
from netops_autopilot.parsers.cisco_show_version import CiscoIosXeShowVersionParser
from netops_autopilot.parsers.keyvalue import KeyValueParser, routeros_system_resource
from netops_autopilot.parsers.registry import ParserRegistry

FIXTURES = simfabric_fixtures_dir()


def _load_golden(rel_dir: str, name: str):
    raw = (FIXTURES / rel_dir / f"{name}.txt").read_bytes()
    expected = json.loads((FIXTURES / rel_dir / f"{name}.expected.json").read_text())
    return raw, expected


def _as_map(observations):
    return {o.field: (o.parse_status, o.value) for o in observations}


def test_golden_routeros_system_resource():
    raw, expected = _load_golden("routeros", "system_resource_print")
    parser = routeros_system_resource()
    assert parser.info.parser_id == expected["parser_id"]
    obs = parser.parse(raw, raw_id="raw-1")
    got = _as_map(obs)
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status.value == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_golden_cisco_show_version():
    raw, expected = _load_golden("cisco_iosxe", "show_version")
    parser = CiscoIosXeShowVersionParser()
    obs = parser.parse(raw, raw_id="raw-2")
    got = _as_map(obs)
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status.value == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_missing_fields_are_typed_missing_never_guessed():
    """L01/T2: absent fields ⇒ MISSING observations, never invented values."""
    raw = b"                   uptime: 1d\n                  version: 7.14.3\n"
    parser = routeros_system_resource()
    got = _as_map(parser.parse(raw, raw_id="raw-3"))
    assert got["uptime"] == (ParseStatus.OK, "1d")
    assert got["board-name"][0] is ParseStatus.MISSING
    assert got["board-name"][1] is None


def test_binary_payload_is_parse_failed_not_crash():
    parser = routeros_system_resource()
    obs = parser.parse(b"\xff\xfe\x00binary", raw_id="raw-4")
    assert all(o.parse_status is ParseStatus.PARSE_FAILED for o in obs)


def test_unparsed_lines_are_observable():
    raw = b"weird banner line\n                  version: 7.14.3\n"
    parser = KeyValueParser("kv/test", "1.0.0", "test", "cmd", ("version",))
    got = _as_map(parser.parse(raw, raw_id="raw-5"))
    assert got["_unparsed_lines"] == (ParseStatus.OK, 1)


def test_registry_semantics():
    reg = ParserRegistry()
    p1 = routeros_system_resource()
    reg.register(p1)
    with pytest.raises(ValueError):
        reg.register(routeros_system_resource())  # same id+version twice
    assert reg.get(p1.info.parser_id, p1.info.version) is p1
    assert reg.latest(p1.info.parser_id) is p1
    with pytest.raises(KeyError):
        reg.get("no/such-parser", "9.9.9")
    # Version ordering for latest()
    newer = KeyValueParser("keyvalue/routeros_system_resource_print", "1.1.0", "mikrotik/routeros", "cmd", ())
    reg.register(newer)
    assert reg.latest("keyvalue/routeros_system_resource_print") is newer
