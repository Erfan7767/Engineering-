"""Every transport test before this file used a double. These use a real pty.

``LoopbackSession`` serves fixture bytes with no prompt, no echo and no baud,
so it cannot show up anything that happens *between* the command and the
answer. Running the real :class:`SerialConsoleTransport` against a real
``/dev/pts/N`` with pySerial opening it exactly as it opens ``/dev/ttyUSB0``
found four defects, each of which broke a different part of a real hardware
run while every simulated run stayed green:

* the connect banner — the only vendor evidence that will ever arrive — was
  discarded, so the operator was asked to name the vendor;
* the device prompt and command echo were returned to the parsers, which
  invented a port called ``seed-01>`` and put ``interface seed-01>`` in both
  the configuration and the rollback plan;
* the crawl closed the operator's console session, so the execution gate found
  ``SESSION_NOT_OPEN``;
* the run passed a ``(session, family)`` tuple where a session belongs, and the
  swallowed exception reported ``IDENTITY_UNVERIFIED`` instead of the real
  cause — so the device on the console cable could never be configured.
"""

from __future__ import annotations

import os

import pytest

from netops_autopilot.access.serial_transport import SerialConsoleTransport, SerialProfile
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.cli_main import _real_mgmt_factory, _real_session_factory
from netops_autopilot.access.vendor_detect import detect_family_candidates
from netops_autopilot.simfabric import make_ledger_stack
from netops_autopilot.simfabric.fabric import _fx, SEED_BANNER, seed_session
from netops_autopilot.simfabric.pty_device import PtyDevice

_ANSWERS = {
    command: _fx(fixture)
    for command, fixture in {
        "show version": "show_version",
        "show lldp neighbors detail": "show_lldp_neighbors_detail",
        "show cdp neighbors detail": "show_cdp_neighbors_detail",
        "show ip route": "show_ip_route",
        "show clock detail": "show_clock",
        "show vlan brief": "show_vlan_brief",
        "show interfaces status": "show_interfaces_status",
    }.items()
}

pytestmark = pytest.mark.skipif(
    not hasattr(os, "openpty"), reason="this platform has no pty"
)


def _device(**kwargs) -> PtyDevice:
    kwargs.setdefault("prompt", b"seed-01> ")
    return PtyDevice(kwargs.pop("answers", _ANSWERS), **kwargs)


def test_open_keeps_bytes_the_device_sent_before_we_spoke() -> None:
    """The banner arrives unasked. It must survive ``open()``.

    ``reset_input_buffer()`` was called first, which discarded exactly the bytes
    that prove what the device is.
    """
    device = _device(banner=SEED_BANNER).start()
    try:
        transport = SerialConsoleTransport(SerialProfile(port=device.port_path))
        transport.open()
        try:
            assert transport.banner, "the connect banner was thrown away"
            assert detect_family_candidates(transport.banner) == ("cisco/ios-xe",)
        finally:
            transport.close()
    finally:
        device.stop()


def test_family_is_detected_without_asking_the_operator() -> None:
    device = _device(banner=SEED_BANNER).start()
    try:
        transport, banner = _real_session_factory(device.port_path)
        try:
            assert detect_family_candidates(banner) == ("cisco/ios-xe",), (
                "a real console run would have stopped and asked the operator "
                "for the vendor"
            )
        finally:
            transport.close()
    finally:
        device.stop()


def test_execute_strips_the_prompt_and_the_command_echo() -> None:
    """What the parser gets must be the device's answer, nothing else."""
    device = _device(banner=SEED_BANNER).start()
    try:
        transport = SerialConsoleTransport(SerialProfile(port=device.port_path))
        transport.open()
        try:
            out = transport.execute("show interfaces status", 2.0)
        finally:
            transport.close()
    finally:
        device.stop()
    assert b"seed-01>" not in out, "the device prompt leaked into the output"
    assert b"show interfaces status" not in out, "the command echo leaked"
    assert b"Gi1/0/8" in out


def test_the_crawl_does_not_close_the_session_it_was_lent() -> None:
    """Discovery closes what it opens. The operator's cable is lent, not opened."""
    device = _device(banner=SEED_BANNER).start()
    try:
        store, kid, _claims, ta = make_ledger_stack()
        engine = AutopilotEngine(
            store=store, key_id=kid, io=ScriptedIO([]), time_authority=ta
        )
        # One console only: two sessions on one pty steal each other's bytes.
        boot = engine._phase_boot_probe(device.port_path, _real_session_factory)
        assert boot[1] == "cisco/ios-xe", boot[1]
        try:
            engine._phase_discovery(
                boot, _real_mgmt_factory(method="ssh", username="lab")
            )
            session = boot[0]
            out = session.execute("show version", 2.0)   # still usable
            assert b"DOG2734L0XX" in out, "the console went dead after discovery"
        finally:
            boot[0].close()
    finally:
        device.stop()


def test_identity_failure_reports_the_read_error_not_a_guess() -> None:
    """A broken session must be reported as broken, not as an unproven identity.

    ``_confirm`` caught every exception and threw it away, so a closed port was
    announced as ``IDENTITY_UNVERIFIED`` and the operator was pointed at
    ``--allow-unverified-identity``, which cannot fix a dead session.
    """
    class Dead:
        def execute(self, command, timeout_s):
            raise RuntimeError("SESSION_NOT_OPEN: call open() first")

    factory = _real_mgmt_factory(method="ssh", username="lab")
    with pytest.raises(Exception) as excinfo:
        factory._confirm("seed-01", "cisco/ios-xe", Dead(), "EXPECTED-SERIAL")
    assert "SESSION_NOT_OPEN" in str(excinfo.value), (
        "the real cause was swallowed and replaced by a plausible guess"
    )


def test_full_run_over_a_real_serial_channel_applies_and_verifies() -> None:
    """The whole run, with real bytes on a real channel, end to end."""
    device = PtyDevice.over(seed_session(), prompt=b"seed-01> ")
    device._banner = SEED_BANNER
    device.start()
    try:
        store, kid, _claims, ta = make_ledger_stack()
        io = ScriptedIO(
            ["y", "guest office", "seed-01", "ISP fiber DHCP handoff", "STANDARD",
             "+25% in 12 months", "1.1.1.1, 9.9.9.9", "BOND"]
        )
        engine = AutopilotEngine(
            store=store, key_id=kid, io=io, time_authority=ta
        )
        report = engine.run(
            probe_port_session_factory=_real_session_factory,
            mgmt_session_factory=_real_mgmt_factory(method="ssh", username="lab"),
            port=device.port_path,
            execute=True,
        )
    finally:
        device.stop()

    boot = next(p for p in report.phases if p.phase.value == "BOOT_PROBE")
    assert "cisco/ios-xe" in str(boot.detail), "the vendor was not auto-detected"
    assert (report.execution or {}).get("outcome") == "APPLIED"
    verification = report.verification or {}
    assert not verification.get("failed"), verification.get("reasons")
    assert len(verification.get("passed") or []) == 15
    # The device really was configured, not just planned.
    sent = [c for c in device.received]
    assert "configure terminal" in sent
    assert any(c.startswith("vlan ") for c in sent)
    # The phantom port the prompt leak used to create would show up here, in
    # both the configuration and the rollback plan.
    plan_text = repr(report.renders) + repr((report.execution or {}).get("not_sent"))
    assert "interface seed-01>" not in plan_text
    assert "default interface seed-01>" not in plan_text
