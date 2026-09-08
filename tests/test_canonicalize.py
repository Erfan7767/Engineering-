"""Canonicalization: port names, VLAN lists, statuses — deterministic."""

import pytest

from netops_autopilot.reconcile.canonicalize import (
    canonical_status,
    canonical_vlan_list,
    normalize_cisco_port,
    normalize_junos_port,
    normalize_routeros_port,
)


@pytest.mark.parametrize("raw,expected", [
    ("Gi1/0/1", "GigabitEthernet1/0/1"),
    ("gi1/0/1", "GigabitEthernet1/0/1"),
    ("GigabitEthernet1/0/1", "GigabitEthernet1/0/1"),
    ("Fa0/1", "FastEthernet0/1"),
    ("Te1/1/1", "TenGigabitEthernet1/1/1"),
    ("Po10", "Port-channel10"),
    ("po10", "Port-channel10"),
    ("Port-channel10", "Port-channel10"),
    ("Vl100", "Vlan100"),
    ("Lo0", "Loopback0"),
    ("Hu1/0/1", "HundredGigE1/0/1"),  # longest-abbrev match: Hu, not H
])
def test_cisco_normalization(raw, expected):
    assert normalize_cisco_port(raw).canonical == expected


def test_cisco_unknown_name_passes_through_flagged():
    """L01: unknown names are never mangled by heuristics."""
    result = normalize_cisco_port("MysteryPort9/9")
    assert result.canonical == "MysteryPort9/9"
    assert result.changed is False
    assert result.rule == "passthrough"


def test_junos_unit_split():
    assert normalize_junos_port("ge-0/0/1.0") == ("ge-0/0/1", 0)
    assert normalize_junos_port("ge-0/0/1") == ("ge-0/0/1", None)
    assert normalize_junos_port("irb.100") == ("irb.100", None)  # non-fpc/pic/port form: unchanged
    assert normalize_junos_port("lo0.0") == ("lo0.0", None)


def test_routeros_whitespace_only():
    assert normalize_routeros_port("  ether1  ").canonical == "ether1"
    assert normalize_routeros_port("bridge1").changed is False


@pytest.mark.parametrize("raw,expected", [
    ("1,3-5,2", "1-5"),
    ("7,7", "7"),
    ("10,11,12,20", "10-12,20"),
    (" 3 , 1 ", "1,3"),
    ("", ""),
])
def test_vlan_list_canonical(raw, expected):
    assert canonical_vlan_list(raw) == expected


def test_vlan_list_invalid_is_typed_error():
    with pytest.raises(ValueError):
        canonical_vlan_list("5-3")
    with pytest.raises(ValueError):
        canonical_vlan_list("0")
    with pytest.raises(ValueError):
        canonical_vlan_list("abc")


@pytest.mark.parametrize("raw,expected", [
    ("up", "up"),
    ("connected", "up"),
    ("notconnect", "down"),
    ("administratively down", "admin_down"),
    ("UP", "up"),
])
def test_status_synonyms(raw, expected):
    canonical, known = canonical_status(raw)
    assert canonical == expected and known


def test_unknown_status_flagged_not_invented():
    canonical, known = canonical_status("dormant")
    assert canonical == "dormant" and known is False
