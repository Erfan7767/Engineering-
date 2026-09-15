"""The web/API control surface drives real hardware, and says what it did.

The API run worker carried its own private copy of the console factory, its own
management factory, and its own positional answer list. Each of the three was
wrong in a way the CLI's equivalent had already been fixed for, or had never
been allowed to be:

* the private console factory read the vendor banner with ``execute("", 1.5)``,
  which returns a prompt and identifies nothing. Every web-initiated run on
  real hardware died at ``FAMILY_UNKNOWN`` before discovery started. Measured:
  ``family=''``, 2 lines sent to the device, run over.
* the management factory refused *every* device, seed included, with the text
  "SSH/telnet management sessions are not enabled in this build" — untrue, the
  CLI enables them. So even past the banner a web run configured nothing.
* the answers were positional and the blueprint slot was the literal ``"2"``,
  so every request built the same network regardless of what the operator asked
  for, and the list was short of the questions the engine asks.

``execute: true`` also could never apply: the flag was passed to the engine
while the apply gate was answered with something that was never the word BOND,
so the run staged everything and denied.

Separately, and shared by every path: when a device stayed unreachable the
executor kept a dry-run change record, and ``DRY_RUN`` fell through the verdict
chain to ``PARTIAL``. The gate then reported ``OK — applied: 0/1`` with
``not_sent``, ``unconfigured_reasons`` and ``failure_decisions`` all empty. A
run that sent nothing read as a run that partly worked.
"""

from __future__ import annotations

import os

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.simfabric import SimFabricFactory, make_ledger_stack

pytestmark = pytest.mark.skipif(not hasattr(os, "openpty"),
                                reason="this platform has no pty")


def _worker(device, *, execute: bool, intent: str | None = None):
    """Run the API worker over an already-open real pty and return its record.

    The device must be created by the caller: opening a second console on the
    same pty makes the two steal each other's bytes, and the run then sees no
    banner at all.
    """
    from netops_autopilot.web import server

    server._RUNS.clear()
    server._RUNS["t"] = server.RunRecord(run_id="t", created_at="now")
    server._run_autopilot_worker("t", device.port_path, execute, False, intent)
    return server._RUNS["t"], list(device.received)


@pytest.fixture
def console():
    from netops_autopilot.simfabric.fabric import SEED_BANNER, seed_session
    from netops_autopilot.simfabric.pty_device import PtyDevice

    device = PtyDevice.over(seed_session(), prompt=b"seed-01> ")
    device._banner = SEED_BANNER
    device.start()
    try:
        yield device
    finally:
        device.stop()


# ---------------------------------------------------------- the banner defect


def test_the_web_worker_identifies_the_device_on_the_console(console):
    """It used to die at FAMILY_UNKNOWN before discovery began."""
    record, sent = _worker(console, execute=False)
    boot = next(p for p in record.report.phases if p.phase.value == "BOOT_PROBE")
    assert "cisco/ios-xe" in str(boot.detail), (
        f"the vendor was not detected from the connect banner: {boot.detail}")
    discovery = next(p for p in record.report.phases
                     if p.phase.value == "DISCOVERY_A")
    assert discovery.status == "OK", discovery.detail


def test_the_web_worker_configures_the_device_on_the_console(console):
    record, sent = _worker(console, execute=True,
                           intent="guest office")
    assert (record.report.execution or {}).get("outcome") == "APPLIED", (
        record.report.final)
    gate = next(p for p in record.report.phases
                if p.phase.value == "EXECUTION_GATE")
    assert "applied: 1/1" in str(gate.detail), gate.detail
    # the configuration really reached the device, not just the plan
    assert "configure terminal" in sent
    assert any(c.startswith("vlan ") for c in sent)
    assert any(c.startswith("ip address ") for c in sent)
    verification = record.report.verification or {}
    assert not verification.get("failed")


def test_execute_false_stages_and_does_not_send(console):
    record, sent = _worker(console, execute=False, intent="branch")
    assert "configure terminal" not in sent, "configuration was sent unasked"


# ----------------------------------------------------------------- the intent


def test_the_operators_intent_reaches_the_blueprint(console):
    record, _sent = _worker(console, execute=False,
                            intent="guest office")
    phase = next(p for p in record.report.phases
                 if p.phase.value == "INTENT_ELICITATION")
    assert "guest_office" in str(phase.detail), phase.detail


@pytest.mark.parametrize("intent,expected",
                         [("guest office", "guest_office"), ("campus", "campus")])
def test_the_requested_network_is_the_one_built(intent, expected):
    """The blueprint slot used to be the literal "2" for every request.

    One device per case: a console prints its banner once, when the line comes
    up, so a second run on the same pty has no vendor evidence to read.
    """
    from netops_autopilot.simfabric.fabric import SEED_BANNER, seed_session
    from netops_autopilot.simfabric.pty_device import PtyDevice

    device = PtyDevice.over(seed_session(), prompt=b"seed-01> ")
    device._banner = SEED_BANNER
    device.start()
    try:
        record, _sent = _worker(device, execute=False, intent=intent)
    finally:
        device.stop()
    phase = next(p for p in record.report.phases
                 if p.phase.value == "INTENT_ELICITATION")
    assert expected in str(phase.detail), phase.detail


# ------------------------------------------------- the management refusal


def test_a_neighbour_is_refused_with_the_true_reason():
    from netops_autopilot.web.server import _ConsoleOnlyMgmt

    factory = _ConsoleOnlyMgmt("/dev/ttyUSB0")
    factory.bind_crawl(None, console_session=object(), seed_ref="seed-01")
    with pytest.raises(Failure) as excinfo:
        factory("access-sw1", ())
    cause = excinfo.value.causes[0]
    assert "NO_MGMT_CREDENTIALS:access-sw1" in cause
    assert "not enabled in this build" not in cause, (
        "the untrue explanation came back")
    assert "netops-autopilot autopilot" in cause, (
        "the operator is not told what to run instead")


def test_the_seed_is_served_from_the_console_session_not_a_second_handle():
    from netops_autopilot.web.server import _ConsoleOnlyMgmt

    console = object()
    factory = _ConsoleOnlyMgmt("/dev/ttyUSB0")
    factory.bind_crawl(None, console_session=console, seed_ref="seed-01")
    assert factory("seed-01", ()) is console


# ------------------------------------------------- the dishonest gate verdict


class _RefusingMgmt:
    """Refuses every device, the way the web worker used to."""

    def __call__(self, device_ref, hints):
        raise Failure(cls=FailureClass.BLOCKED,
                      causes=(f"NO_MGMT_CREDENTIALS:{device_ref}",))


def test_a_gate_that_sent_nothing_does_not_report_ok():
    """``OK — applied: 0/1`` with every reason field empty."""
    from netops_autopilot.autopilot.answer_script import answers_keyed

    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    store, key_id, _counters, ta = make_ledger_stack()
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(dict(answers_keyed(access_retry="n", intent="branch",
                                         apply=True))),
        time_authority=ta)
    report = engine.run(probe_port_session_factory=fabric.probe,
                        mgmt_session_factory=_RefusingMgmt(),
                        port="SIM0", execute=True)
    gate = next(p for p in report.phases if p.phase.value == "EXECUTION_GATE")
    assert gate.status != "OK", (
        f"the gate authorised an apply, sent nothing, and said OK: {gate.detail}")
    assert "NOTHING SENT" in str(gate.detail), gate.detail
    assert (report.execution or {}).get("outcome") == "NOTHING_APPLIED", (
        report.execution or {}).get("outcome")
    # and the reason is in the detail, not only buried in change_records
    assert "DEVICE_UNREACHABLE" in str(gate.detail) or "NO_MGMT" in str(gate.detail)


def test_a_run_that_really_applies_still_reports_ok():
    """The guard above must not make an honest apply look incomplete."""
    from netops_autopilot.autopilot.answer_script import answers_keyed

    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    store, key_id, _counters, ta = make_ledger_stack()
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(dict(answers_keyed(access_retry="n", intent="branch",
                                         apply=True))),
        time_authority=ta)
    report = engine.run(probe_port_session_factory=fabric.probe,
                        mgmt_session_factory=fabric.open,
                        port="SIM0", execute=True)
    gate = next(p for p in report.phases if p.phase.value == "EXECUTION_GATE")
    assert gate.status == "OK", gate.detail
    assert (report.execution or {}).get("outcome") == "APPLIED"
