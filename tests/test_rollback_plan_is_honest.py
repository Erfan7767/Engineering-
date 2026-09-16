"""The rollback plan must describe what is really left to undo.

Two failure modes are equally dangerous and point in opposite directions:

* **A false alarm.** FortiOS renders ``config system global`` and
  ``config system interface``, which *enter* a configuration section and
  change nothing until a ``set`` runs — the allowlist's own purpose text
  says so. They declare no inverse because there is nothing to invert.
  Treating them as unfinished work made **every** FortiOS rollback report
  ``ROLLBACK_FAILED`` with ``ROLLBACK_INCOMPLETE_MANUAL_STEPS_REQUIRED``,
  on a device that had been restored. An operator who learns that signal
  lies stops believing it the day it is true.
* **A false all-clear.** A command that *does* change state and declares
  no inverse really is unfinished work, and must keep demanding a manual
  step. Suppressing that would report a partially configured device as
  clean.

The discriminator is ``enters_mode`` combined with the absence of an
inverse: a section entry is inert; anything else is a change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netops_autopilot.access.allowlist import (
    AllowlistEntry,
    CommandAllowlist,
)
from netops_autopilot.access.executor import (
    CONFIG_CLASSES,
    ChangeOutcome,
    ConfigExecutor,
    _build_rollback_plan,
    _PlannedLine,
)
from netops_autopilot.engines.config_ir import (
    ConfigIR,
    EntityRef,
    IRNode,
    Operation,
    Reversibility,
)
from netops_autopilot.engines.config_renderer import _RENDERER_FILES, render_ir
from netops_autopilot.simfabric.loopback import LoopbackSession
from netops_autopilot.specs_data import specs_data_dir

_ALLOWLIST_DIR = specs_data_dir("allowlists")

#: renderer key -> the ``vendor_family`` its allowlist is registered under.
_VENDOR_OF = {
    "ios": "cisco/ios-xe",
    "ios-xe": "cisco/ios-xe",
    "routeros": "mikrotik/routeros",
    "junos": "juniper/junos",
    "arubaos": "aruba/arubaos",
    "fortios": "fortinet/fortios",
}

_PARAMS = {
    "vlan_id": "10",
    "name": "Vlan10",
    "hostname": "dev-01",
    "address_ip": "10.240.0.1",
    "address_mask": "255.255.255.192",
    "interface": "Gi1/0/1",
    "description": "uplink",
    "pool": "users",
    "exclude_first": "10.240.0.2",
    "exclude_last": "10.240.0.10",
    "acl_name": "ISO-users",
    "src_net": "10.240.0.0",
    "src_wc": "0.0.0.63",
    "dst_net": "10.240.0.128",
    "dst_wc": "0.0.0.63",
    "network": "10.240.0.0/26",
    "gateway": "10.240.0.62",
}


def _fortios_allowlist() -> CommandAllowlist:
    return CommandAllowlist.load_vendor(_ALLOWLIST_DIR, "fortinet/fortios")


def _fortios_commands() -> list[str]:
    """The commands the FortiOS renderer really produces."""
    nodes = tuple(
        IRNode(
            node_id=f"n{i}",
            target=EntityRef("DEVICE", "fgt-01"),
            operation=Operation.CREATE,
            feature=feature,
            vendor_os="fortios",
            parameters=_PARAMS,
            reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
        )
        for i, feature in enumerate(("hostname", "vlan", "svi"))
    )
    rendered = render_ir("fgt-01", ConfigIR(title="t", nodes=nodes))
    return [c for b in rendered.blocks for c in b.commands]


def _line(command: str, allowlist: CommandAllowlist, depth: int = 0) -> _PlannedLine:
    """Plan a line the way the executor does, from its allowlist match."""
    match = allowlist.match(command)
    assert match is not None, f"{command!r} is not allowlisted"
    assert match.cls in CONFIG_CLASSES, f"{command!r} is not a CONFIG class"
    return _PlannedLine(command, command, "CONFIG", match.cls, match,
                        depth, match.entry.enters_mode)


def _markers(plan: list[tuple[str, int]]) -> list[str]:
    return [cmd for cmd, _ in plan if cmd.startswith("!")]


# --------------------------------------------------------------------------
# The false alarm: inert section entries
# --------------------------------------------------------------------------


def test_fortios_section_entries_are_not_left_to_a_human() -> None:
    """``config system …`` changes nothing, so nothing is left to undo."""
    allowlist = _fortios_allowlist()
    commands = _fortios_commands()
    assert "config system global" in commands
    assert "config system interface" in commands

    plan = _build_rollback_plan(
        [_line(c, allowlist) for c in commands], allowlist)

    assert _markers(plan) == []


def test_the_state_changing_lines_still_get_a_real_inverse() -> None:
    """The fix must not empty the plan — the ``set`` lines are the change."""
    allowlist = _fortios_allowlist()
    commands = _fortios_commands()

    plan = _build_rollback_plan(
        [_line(c, allowlist) for c in commands], allowlist)
    inverses = [cmd for cmd, _ in plan]

    assert "unset vlanid" in inverses
    assert "unset ip" in inverses


def test_edit_keeps_its_inverse_because_it_selects_something() -> None:
    """``edit Vlan10`` enters a mode *and* has an inverse, so it stays."""
    allowlist = _fortios_allowlist()
    match = allowlist.match("edit Vlan10")

    assert match.entry.enters_mode is True
    assert allowlist.resolve_inverse("edit Vlan10") is not None


def test_a_rolled_back_fortios_run_reports_no_manual_steps() -> None:
    """End to end: the causes an operator reads carry no false manual step."""
    session = LoopbackSession()
    session.fail_times["set vlanid 10"] = 1
    executor = ConfigExecutor(allowlist=_fortios_allowlist(), run_id="r1")

    record = executor.apply("fgt-01", session, _fortios_commands())

    joined = "\n".join(record.failure_causes)
    assert "MANUAL_ROLLBACK_REQUIRED" not in joined
    assert "ROLLBACK_INCOMPLETE_MANUAL_STEPS_REQUIRED" not in joined
    # The real failure is still named — this is a repair, not a cover-up.
    assert "COMMAND_FAILED:set vlanid 10" in joined


# --------------------------------------------------------------------------
# The false all-clear: a real change with no inverse
# --------------------------------------------------------------------------


def _allowlist_with(enters_mode: bool) -> CommandAllowlist:
    """A minimal allowlist whose one CONFIG entry declares *no* inverse.

    The only variable is ``enters_mode``, so the pair of tests below is a
    true A/B on the one fact the executor is allowed to rely on.
    """
    entries = [
        AllowlistEntry(template="show running-config", cls="READ_ONLY"),
        AllowlistEntry(template="exit", cls="MODE_TRANSITION"),
        AllowlistEntry(template="configure thing", cls="CONFIG_REVERSIBLE",
                       rollback="", enters_mode=enters_mode),
        AllowlistEntry(template="set value <v>", cls="CONFIG_REVERSIBLE",
                       rollback="unset value"),
    ]
    return CommandAllowlist(entries=tuple(entries))


def test_a_change_with_no_inverse_still_demands_a_manual_step() -> None:
    """``enters_mode=False`` + no inverse = unfinished work, still flagged."""
    allowlist = _allowlist_with(enters_mode=False)
    plan = _build_rollback_plan(
        [_line("configure thing", allowlist)], allowlist)

    markers = _markers(plan)
    assert len(markers) == 1
    assert "MANUAL_ROLLBACK_REQUIRED" in markers[0]
    assert "configure thing" in markers[0]


def test_a_change_with_no_inverse_makes_the_rollback_fail() -> None:
    """And that flag must still drive the outcome an operator acts on."""
    allowlist = _allowlist_with(enters_mode=False)
    session = LoopbackSession()
    session.fail_times["set value 7"] = 1
    executor = ConfigExecutor(allowlist=allowlist, run_id="r2")

    record = executor.apply(
        "dev-01", session, ["configure thing", "set value 7"])

    assert record.outcome is ChangeOutcome.ROLLBACK_FAILED
    assert "ROLLBACK_INCOMPLETE_MANUAL_STEPS_REQUIRED" in record.failure_causes


def test_an_inert_entry_with_no_inverse_is_not_rolled_back_by_hand() -> None:
    """The same entry, marked as a section entry, is inert — no marker."""
    allowlist = _allowlist_with(enters_mode=True)
    plan = _build_rollback_plan(
        [_line("configure thing", allowlist)], allowlist)

    assert _markers(plan) == []


# --------------------------------------------------------------------------
# Repo-wide invariants, so the next renderer cannot regress either side
# --------------------------------------------------------------------------


@pytest.mark.parametrize("family", sorted(_RENDERER_FILES))
def test_every_rendered_command_is_authorised_by_its_own_allowlist(
        family: str) -> None:
    """A renderer may never emit a line its allowlist would refuse.

    This is the check that caught Junos and RouterOS emitting commands
    their own allowlists did not authorise. It was applied by hand once;
    this makes it permanent.
    """
    allowlist = CommandAllowlist.load_vendor(
        _ALLOWLIST_DIR, _VENDOR_OF[family])
    spec = json.loads(Path(
        specs_data_dir("renderers", _RENDERER_FILES[family])).read_text("utf-8"))

    unauthorised = []
    for feature in sorted(spec.get("features", {})):
        node = IRNode(node_id="n", target=EntityRef("DEVICE", "dev-01"),
                      operation=Operation.CREATE, feature=feature,
                      vendor_os=family, parameters=_PARAMS,
                      reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
        for block in render_ir("dev-01", ConfigIR(title="t", nodes=(node,))).blocks:
            for command in block.commands:
                if allowlist.gate(command.strip()) is None:
                    unauthorised.append((feature, command.strip()))

    assert unauthorised == []


@pytest.mark.parametrize("family", sorted(_RENDERER_FILES))
def test_every_rendered_command_is_undoable_or_inert(family: str) -> None:
    """No rendered line may be a change the platform cannot reverse.

    Every command must either declare an inverse or be a section entry
    that changes nothing. Anything else would silently become a manual
    step on a real device.
    """
    allowlist = CommandAllowlist.load_vendor(
        _ALLOWLIST_DIR, _VENDOR_OF[family])
    spec = json.loads(Path(
        specs_data_dir("renderers", _RENDERER_FILES[family])).read_text("utf-8"))

    unundoable = []
    for feature in sorted(spec.get("features", {})):
        node = IRNode(node_id="n", target=EntityRef("DEVICE", "dev-01"),
                      operation=Operation.CREATE, feature=feature,
                      vendor_os=family, parameters=_PARAMS,
                      reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
        for block in render_ir("dev-01", ConfigIR(title="t", nodes=(node,))).blocks:
            for command in block.commands:
                stripped = command.strip()
                match = allowlist.match(stripped)
                if match is None:
                    continue  # covered by the authorisation test above
                if allowlist.resolve_inverse(stripped) is None \
                        and not match.entry.enters_mode:
                    unundoable.append((feature, stripped))

    assert unundoable == []
