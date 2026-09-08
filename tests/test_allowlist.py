"""Command Allowlist enforcement (D0 data + access/allowlist.py)."""

from pathlib import Path

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist

ALLOWLIST_DIR = Path(__file__).resolve().parents[1] / "specs" / "data" / "allowlists"


def test_loads_all_six_vendor_files():
    al = CommandAllowlist.load_dir(ALLOWLIST_DIR)
    assert al.size() > 0
    files = sorted(p.name for p in ALLOWLIST_DIR.glob("*.json"))
    assert files == [
        "arubaos.json", "cisco_iosxe.json", "fortios.json",
        "junos.json", "routeros.json", "unifi.json",
    ]


def test_readonly_commands_classified():
    al = CommandAllowlist.load_dir(ALLOWLIST_DIR)
    assert al.is_readable("show version")
    assert al.is_readable("/system/resource/print")
    assert al.classify("show version") == "READ_ONLY"


def test_unregistered_command_is_never_allowed():
    """L10/T3: anything outside the allowlist has no execution path."""
    al = CommandAllowlist.load_dir(ALLOWLIST_DIR)
    assert al.classify("delete /force /recursive flash:") is None
    assert not al.is_readable("delete /force /recursive flash:")
    assert al.classify("show versio") is None  # typos are not fuzzy-matched


def test_forbidden_class_present_for_destructive_commands():
    al = CommandAllowlist.load_dir(ALLOWLIST_DIR)
    assert al.classify("write erase") == "FORBIDDEN"
    assert al.classify("erase <args>") == "FORBIDDEN"
    assert not al.is_readable("write erase")


def test_destructive_entries_marked_human_task_only():
    al = CommandAllowlist.load_dir(ALLOWLIST_DIR)
    entry = al.entry("/system/netinstall <args>")
    assert entry is not None and entry.cls == "DESTRUCTIVE"


def test_duplicate_template_across_classes_rejected():
    with pytest.raises(ValueError):
        CommandAllowlist((
            AllowlistEntry(template="show version", cls="READ_ONLY"),
            AllowlistEntry(template="show version", cls="FORBIDDEN"),
        ))
