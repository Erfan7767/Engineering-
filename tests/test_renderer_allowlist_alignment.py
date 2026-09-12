"""Every command a renderer can emit must clear the vendor's allowlist.

T3: no CONFIG without an allowlist entry. That law is enforced at execution
time, so a renderer template with no matching entry does not fail loudly — it
fails at the moment the run reaches the device, after the operator has already
approved the preview. This test moves the failure to the commit that introduces
it.

It caught a real gap: the ArubaOS renderer emits ``write memory`` to make the
change survive a reload, and the ArubaOS allowlist had no ``CONFIG_PERSIST``
class at all, so persist would have been refused after a successful apply.

Mode-transition wrappers (``configure terminal``, ``end``) are deliberately
outside the CONFIG gate — they live in the executor's closed
``SAFE_MODE_TRANSITIONS`` set, which this test checks too. A wrapper that is in
neither place is a configuration command being smuggled past the gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netops_autopilot.access.allowlist import CONFIG_CLASSES, PERSIST_CLASSES
from netops_autopilot.access.executor import SAFE_MODE_TRANSITIONS
from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.engines.config_renderer import _RENDERER_FILES

RENDERER_DIR = Path("specs/data/renderers")
ALLOWLIST_DIR = Path("specs/data/allowlists")

#: vendor_os -> (allowlist filename, vendor_family value inside that file)
_ALLOWLIST_FOR = {
    "ios-xe": ("cisco_iosxe.json", "cisco/ios-xe"),
    "ios": ("cisco_iosxe.json", "cisco/ios-xe"),
    "junos": ("junos.json", "juniper/junos"),
    "routeros": ("routeros.json", "mikrotik/routeros"),
    "arubaos": ("arubaos.json", "aruba/arubaos"),
}

#: Sample values for every placeholder any renderer template uses. A template
#: referencing a placeholder absent here raises, which is itself a finding: the
#: renderer would emit `KeyError` at runtime and mark the node NOT_MODELED.
SAMPLES = {
    "vlan_id": "10",
    "name": "users",
    "address": "10.240.0.1/25",
    "address_ip": "10.240.0.1",
    "address_mask": "255.255.255.128",
    "interface": "gi1/0/1",
    "parent": "ether1",
    "description": "uplink-to-core",
    "allowed_vlans_csv": "10,20,30",
    "hostname": "edge-sw1",
    "exclude_first": "10.240.0.1",
    "exclude_last": "10.240.0.10",
    "pool": "users",
    "network": "10.240.0.0",
    "netmask": "255.255.255.128",
    "gateway": "10.240.0.1",
    "dns": "1.1.1.1",
    "domain": "corp.example",
}


def _allowlist(vendor_os: str) -> CommandAllowlist:
    """`load_vendor` takes the directory and matches on the family id inside."""
    filename, family = _ALLOWLIST_FOR[vendor_os]
    assert (ALLOWLIST_DIR / filename).exists(), f"missing {ALLOWLIST_DIR / filename}"
    return CommandAllowlist.load_vendor(ALLOWLIST_DIR, family)


def _render(template: str) -> tuple[str, bool]:
    """Substitute every placeholder, honouring the `? ` optional marker."""
    optional = template.startswith("? ")
    body = template[2:] if optional else template
    return body.format(**SAMPLES), optional


# ===================================================== the invariant itself
@pytest.mark.parametrize("vendor_os", sorted(_RENDERER_FILES))
def test_every_feature_command_is_allowlisted(vendor_os):
    data = json.loads((RENDERER_DIR / _RENDERER_FILES[vendor_os]).read_text("utf-8"))
    al = _allowlist(vendor_os)
    offenders = []
    for feature, spec in data.get("features", {}).items():
        for template in list(spec.get("commands", ())) + list(spec.get("prelude", ())):
            line, _optional = _render(template)
            line = line.strip()
            if not line:
                continue
            klass = al.gate(line)
            if klass not in CONFIG_CLASSES:
                offenders.append(f"{feature}: {line!r} -> {klass}")
    assert not offenders, (
        f"{vendor_os}: these rendered commands are not allowlisted as CONFIG, "
        f"so the executor would refuse them after the operator approved:\n  "
        + "\n  ".join(offenders))


@pytest.mark.parametrize("vendor_os", sorted(_RENDERER_FILES))
def test_persist_command_is_allowlisted_as_persist(vendor_os):
    """Persist runs *after* a verified apply; refusing it loses the change."""
    data = json.loads((RENDERER_DIR / _RENDERER_FILES[vendor_os]).read_text("utf-8"))
    al = _allowlist(vendor_os)
    for line in data.get("wrappers", {}).get("persist", ()):
        assert al.gate(line) in PERSIST_CLASSES, (
            f"{vendor_os}: persist command {line!r} gates as "
            f"{al.gate(line)!r}, not one of {PERSIST_CLASSES}")


@pytest.mark.parametrize("vendor_os", sorted(_RENDERER_FILES))
def test_mode_wrappers_are_in_the_closed_transition_set(vendor_os):
    """A wrapper outside SAFE_MODE_TRANSITIONS is config smuggled past the gate."""
    data = json.loads((RENDERER_DIR / _RENDERER_FILES[vendor_os]).read_text("utf-8"))
    wrappers = data.get("wrappers", {})
    for key in ("enter_config", "exit_config"):
        for line in wrappers.get(key, ()):
            assert line in SAFE_MODE_TRANSITIONS, (
                f"{vendor_os}: {key} wrapper {line!r} is not in "
                f"SAFE_MODE_TRANSITIONS — mode wrappers change no state, so "
                f"anything else is a configuration command")


@pytest.mark.parametrize("vendor_os", sorted(_RENDERER_FILES))
def test_the_executor_will_plan_every_renderer_output(vendor_os):
    """The real gate: ``ConfigExecutor._plan`` accepts the rendered body.

    This catches what per-line gating cannot. ``_plan`` refuses an indented
    line unless the previous command opened a sub-mode, and it decides that
    from the allowlist entry's ``enters_mode`` flag. ArubaOS nests like Cisco
    but its allowlist declared ``enters_mode`` on nothing, so every indented
    line — ``ip address`` under ``interface vlan 10``, ``switchport …`` under
    ``interface gi1/0/1`` — was refused with INDENT_WITHOUT_MODE_ENTRY. The
    commands were allowlisted and still could never run.
    """
    from netops_autopilot.access.executor import ConfigExecutor

    data = json.loads((RENDERER_DIR / _RENDERER_FILES[vendor_os]).read_text("utf-8"))
    al = _allowlist(vendor_os)
    ex = ConfigExecutor(allowlist=al)
    wrappers = data.get("wrappers", {})
    body = []
    for feature, spec in data.get("features", {}).items():
        for template in spec.get("commands", ()):
            line, optional = _render(template)
            if not line.strip():
                continue
            body.append(line)
    plan = ex._plan(list(wrappers.get("enter_config", ())), body,
                    list(wrappers.get("exit_config", ())))
    assert plan, f"{vendor_os}: the renderer produced no plannable lines"
    for line in plan:
        assert line.kind in ("CONFIG", "MODE", "COMMENT"), (vendor_os, line.stripped)
        if line.kind == "CONFIG":
            assert line.cls in CONFIG_CLASSES, (vendor_os, line.stripped, line.cls)


# ============================================ every renderer is registered
def test_every_renderer_file_is_registered():
    """A renderer file nobody loads is a vendor that silently cannot be built."""
    registered = set(_RENDERER_FILES.values())
    on_disk = {p.name for p in RENDERER_DIR.glob("*.json")}
    assert on_disk <= registered, sorted(on_disk - registered)
    assert registered <= on_disk, sorted(registered - on_disk)


def test_unverified_renderers_say_so():
    """`verified` drives the PREVIEW label; a false claim would hide risk."""
    for vendor_os, filename in _RENDERER_FILES.items():
        data = json.loads((RENDERER_DIR / filename).read_text("utf-8"))
        if not data.get("verified"):
            assert data.get("note"), (
                f"{vendor_os}: verified=false must carry a note explaining what "
                f"is and is not lab-verified")
            assert data.get("verified_at") is None, (
                f"{vendor_os}: verified_at is set while verified is false")
