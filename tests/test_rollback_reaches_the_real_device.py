"""Rollback really reaches the device, and a failed rollback says so.

The rollback plan is built from the inverse of every command that was applied,
and the executor's own contract is that ``ROLLED_BACK`` is only reported when
every issued inverse was accepted and the running-config is back to the
baseline. That contract had never been checked against a real channel: every
existing rollback test used an in-process session double, which cannot show
whether the inverse lines were actually written to the wire, in the right
order, at the right mode depth.

These run the real ``SerialConsoleTransport`` over a real pty, with the device
behind it made to reject one command mid-apply — which is what a refused line
or a flapping console looks like from the executor's side. The assertion is on
what the device *received*, not on what the report claims.
"""

from __future__ import annotations

import os

import pytest

from netops_autopilot.autopilot.answer_script import answers_keyed
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.cli_main import _real_mgmt_factory, _real_session_factory
from netops_autopilot.simfabric import make_ledger_stack
from netops_autopilot.simfabric.fabric import SEED_BANNER, seed_session
from netops_autopilot.simfabric.pty_device import PtyDevice

pytestmark = pytest.mark.skipif(not hasattr(os, "openpty"),
                                reason="this platform has no pty")


def _run_with(failures: dict[str, int]):
    """Run the real console path against a device that rejects given commands.

    Returns ``(report, lines_the_device_actually_received)``.
    """
    backend = seed_session()
    for command, times in failures.items():
        backend.fail_times[command] = times
    device = PtyDevice.over(backend, prompt=b"seed-01> ")
    device._banner = SEED_BANNER
    device.start()
    try:
        store, key_id, _counters, ta = make_ledger_stack()
        engine = AutopilotEngine(
            store=store, key_id=key_id,
            io=ScriptedIO(dict(answers_keyed(access_retry="n",
                                             intent="guest office",
                                             apply=True))),
            time_authority=ta)
        report = engine.run(
            probe_port_session_factory=_real_session_factory,
            mgmt_session_factory=_real_mgmt_factory(method="ssh", username="lab"),
            port=device.port_path, execute=True)
        return report, list(device.received)
    finally:
        device.stop()


def test_a_clean_apply_sends_the_configuration_and_nothing_to_undo():
    report, sent = _run_with({})
    assert (report.execution or {}).get("outcome") == "APPLIED", report.final
    assert any(c.startswith("vlan ") for c in sent)
    assert not [c for c in sent if c.startswith(("no ", "default "))], (
        "a successful apply issued inverse commands")


def test_when_a_line_is_rejected_the_inverses_really_reach_the_device():
    """The report said ROLLED_BACK; this checks the wire."""
    report, sent = _run_with({"vlan 20": 1})
    decisions = (report.execution or {}).get("failure_decisions") or []
    assert decisions, "a rejected line produced no recorded decision"
    assert decisions[0]["executor_outcome"] == "ROLLED_BACK", decisions[0]

    inverses = [c for c in sent if c.startswith(("no ", "default "))]
    assert inverses, "the report claimed a rollback but nothing was sent back"
    # The inverse of an access-port assignment, actually on the wire.
    assert any(c.startswith("default interface ") for c in inverses), inverses[:8]
    assert any(c == "no switchport access vlan" for c in inverses), inverses[:8]


def test_the_inverses_come_after_the_commands_they_undo():
    """Order matters: an inverse sent before its command undoes nothing."""
    _report, sent = _run_with({"vlan 20": 1})
    assert "configure terminal" in sent
    first_undo = next(i for i, c in enumerate(sent)
                      if c.startswith(("no ", "default ")))
    last_config = max(i for i, c in enumerate(sent[:first_undo])
                      if c.startswith(("vlan ", "interface ", "ip address ")))
    assert last_config < first_undo, (
        f"an inverse at {first_undo} preceded the configuration at {last_config}")


def test_a_rollback_that_itself_fails_is_never_reported_as_clean():
    """The dangerous case: apply failed and the device could not be restored.

    Reporting ROLLED_BACK here would tell an operator the box is back to its
    baseline when it is not. The executor's contract is ROLLBACK_FAILED with a
    typed cause, and the run-level verdict must block.
    """
    report, sent = _run_with({
        "vlan 20": 1,
        "default interface gi1/0/11": 99,   # an inverse the device refuses
    })
    assert report.final == "BLOCKED-ROLLBACK-FAILED", report.final
    assert (report.execution or {}).get("outcome") == "ROLLBACK_FAILED"
    # The executor's own verdict, not the run-level one. The decision layer
    # can reach the right conclusion independently, which is good, but a
    # test that only checks the run verdict would not notice the executor
    # calling a failed rollback clean.
    records = (report.execution or {}).get("change_records") or []
    assert records, "no change record was kept"
    assert records[0]["outcome"] == "ROLLBACK_FAILED", records[0]["outcome"]
    decisions = (report.execution or {}).get("failure_decisions") or []
    assert decisions and decisions[0]["decision"] == "HALT", decisions
    causes = " ".join(decisions[0].get("reasons") or [])
    assert "ROLLBACK_STATE" in causes or "ROLLBACK_COMMAND_FAILED" in causes, causes
    # and the attempt was still made — the platform did not give up silently
    assert [c for c in sent if c.startswith(("no ", "default "))], (
        "no inverse was even attempted")


def test_the_device_is_told_what_state_it_was_left_in():
    """`DEVICE_MAY_BE_LEFT_IN_PARTIAL_STATE` is the operator's cue."""
    report, _sent = _run_with({
        "vlan 20": 1,
        "default interface gi1/0/11": 99,
    })
    records = (report.execution or {}).get("change_records") or []
    assert records, "no change record was kept for the device"
    causes = " ".join(records[0].get("failure_causes") or [])
    assert "DEVICE_MAY_BE_LEFT_IN_PARTIAL_STATE" in causes or \
           "ROLLBACK_STATE_MISMATCH" in causes, causes
