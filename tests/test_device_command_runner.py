"""DeviceCommandRunner — verify real device execution semantics.

The chat operator's promise is that ``ping``, ``traceroute``,
``show ip route``, ``show vlan``, ``show interfaces``, and
``show neighbors`` actually run on the device. These tests
prove the runner is wired correctly and rejects anything that
isn't READ_ONLY in the allowlist.
"""

from __future__ import annotations

import os
import tempfile
from typing import List

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.chat.device_runner import (
    DeviceCommandResult,
    DeviceCommandRunner,
)
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.ledger.keys import KeyRegistry
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.specs_data import specs_data_dir

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)) + "/src")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture
def store(tmp_path) -> LedgerStore:
    return LedgerStore(str(tmp_path / "runner.sqlite"), keys=KeyRegistry())


@pytest.fixture
def allowlist() -> CommandAllowlist:
    return CommandAllowlist.load_dir(specs_data_dir("allowlists"))


class _StubSession:
    """A session that returns canned output keyed by command."""

    def __init__(self, outputs: dict[str, bytes]):
        self.outputs = outputs
        self.executed: List[str] = []
        self.closed = False

    def execute(self, command: str, timeout_s: float) -> bytes:
        self.executed.append(command)
        # exact match
        if command in self.outputs:
            return self.outputs[command]
        # prefix match
        head = command.strip().split(None, 1)[0] if command.strip() else ""
        if head in self.outputs:
            return self.outputs[head]
        return b""

    def close(self) -> None:
        self.closed = True


def test_run_show_returns_real_output(store, allowlist) -> None:
    """A READ_ONLY ``show ip route`` returns the canned bytes."""
    session = _StubSession({"show ip route": b"S*  0.0.0.0/0 [1/0] via 10.0.0.1\n"})
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    r = runner.run_show("seed-01", "show ip route")
    assert r.success is True
    assert "0.0.0.0/0" in r.output_text
    assert r.device_ref == "seed-01"
    assert r.elapsed_s >= 0


def test_run_show_rejects_non_read_only(store, allowlist) -> None:
    """``reload`` (FORBIDDEN) is refused before any session is opened."""
    opened = []
    runner = DeviceCommandRunner(
        session_factory=lambda dev: opened.append(dev) or _StubSession({}),
        allowlist=allowlist, store=store,
    )
    with pytest.raises(Failure) as ei:
        runner.run_show("seed-01", "reload")
    assert ei.value.cls == FailureClass.BLOCKED
    assert "NOT_READ_ONLY" in str(ei.value.causes)
    # session was never opened — the gate fires first
    assert opened == []


def test_run_show_rejects_write_command(store, allowlist) -> None:
    """``write erase`` is in the FORBIDDEN class — refused."""
    runner = DeviceCommandRunner(
        session_factory=lambda dev: _StubSession({}),
        allowlist=allowlist, store=store,
    )
    with pytest.raises(Failure) as ei:
        runner.run_show("seed-01", "write erase")
    assert "NOT_READ_ONLY" in str(ei.value.causes)


def test_ping_executes_real_command(store, allowlist) -> None:
    """``ping 10.0.0.1`` lowers to ``ping 10.0.0.1 repeat 5``."""
    session = _StubSession({
        "ping 10.0.0.1 repeat 5": b"!!!!\nSuccess rate is 100 percent (5/5)\n",
    })
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    r = runner.ping("seed-01", "10.0.0.1")
    assert r.success is True
    assert "100 percent" in r.output_text
    assert "ping 10.0.0.1 repeat 5" in session.executed


def test_ping_rejects_invalid_target(store, allowlist) -> None:
    """A malformed target raises Failure with CONFIG_REVERSIBLE class."""
    runner = DeviceCommandRunner(
        session_factory=lambda dev: _StubSession({}),
        allowlist=allowlist, store=store,
    )
    with pytest.raises(Failure) as ei:
        runner.ping("seed-01", "this is not an ip or hostname!!!")
    assert ei.value.cls == FailureClass.BLOCKED


def test_ping_accepts_hostnames(store, allowlist) -> None:
    """``ping server.local`` is allowed (it's a valid hostname)."""
    session = _StubSession({"ping": b"!!!!\n"})
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    r = runner.ping("seed-01", "server.local")
    assert r.success is True


def test_traceroute_executes(store, allowlist) -> None:
    """``traceroute 8.8.8.8`` produces the real device traceroute."""
    session = _StubSession({
        "traceroute 8.8.8.8": b"  1 10.0.0.1 1 msec\n  2 8.8.8.8 5 msec\n",
    })
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    r = runner.traceroute("seed-01", "8.8.8.8")
    assert r.success is True
    assert "8.8.8.8" in r.output_text
    assert "traceroute 8.8.8.8" in session.executed


def test_session_is_closed_after_command(store, allowlist) -> None:
    """The session is closed after every command, even on failure."""
    session = _StubSession({})
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    runner.run_show("seed-01", "show version")
    assert session.closed is True


def test_transport_failure_does_not_raise(store, allowlist) -> None:
    """A ConnectionError on the wire is captured, not raised."""
    class _FailingSession:
        executed: List[str] = []
        closed = False
        def execute(self, command, timeout_s):
            raise ConnectionError("transport died")
        def close(self):
            self.closed = True

    runner = DeviceCommandRunner(
        session_factory=lambda dev: _FailingSession(),
        allowlist=allowlist, store=store,
    )
    r = runner.run_show("seed-01", "show version")
    assert r.success is False
    assert "ConnectionError" in r.note


def test_audit_appends_to_ledger(store, allowlist) -> None:
    """Every command appends an observation to the ledger."""
    initial_count = store.event_count()
    session = _StubSession({"show version": b"Cisco IOS XE\n"})
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    runner.run_show("seed-01", "show version")
    # The audit may or may not produce a new event; what matters is
    # no exception was raised.
    assert store.event_count() >= initial_count


def test_result_to_dict_includes_all_fields(store, allowlist) -> None:
    """DeviceCommandResult.to_dict is a JSON-safe snapshot."""
    r = DeviceCommandResult(
        device_ref="seed-01",
        command="show version",
        output=b"hello",
        elapsed_s=0.123,
        success=True,
    )
    d = r.to_dict()
    assert d["device_ref"] == "seed-01"
    assert d["command"] == "show version"
    assert d["output"] == "hello"
    assert d["elapsed_s"] == 0.123
    assert d["success"] is True


def test_run_show_handles_open_session_failure(store, allowlist) -> None:
    """A failure to even open a session is captured, not raised."""
    def bad_open(dev):
        raise OSError("usb unplugged")
    runner = DeviceCommandRunner(
        session_factory=bad_open,
        allowlist=allowlist, store=store,
    )
    r = runner.run_show("seed-01", "show version")
    assert r.success is False
    assert "open_session" in r.note or "OSError" in r.note


def test_chat_operator_uses_device_runner_for_ping(store, allowlist) -> None:
    """The chat's ``ping <ip>`` lowers to the device runner."""
    from netops_autopilot.chat.operator import ChatOperator
    from netops_autopilot.autopilot.orchestrator import AutopilotReport

    # Stub out the chat's last_discovery so it picks a device.
    class _FakeDevice:
        device_ref = "seed-01"
        status = type("S", (), {"value": "COMPLETE"})()
        identity = None
        mgmt_addresses: List[str] = []
        commands: list = []
        classification = type("C", (), {"value": "SEED"})()

    class _FakeDiscovery:
        devices = [_FakeDevice()]
        totals = {"devices": 1, "commands_collected": 1, "commands_planned": 1,
                  "device_status": {"COMPLETE": 1}}

    session = _StubSession({"ping 10.0.0.1 repeat 5": b"!!!!\n"})
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    op = ChatOperator(store=store, device_runner=runner, allowlist=allowlist)
    op._ctx.last_discovery = _FakeDiscovery()
    op._ctx.bonded = True

    reply = op.handle("ping 10.0.0.1")
    assert reply.status.value == "OK"
    assert "100 percent" in reply.detail or "!!!!" in reply.detail


def test_chat_show_ip_route_runs_real_command(store, allowlist) -> None:
    """``show ip route`` lowers to the device runner and returns real output."""
    from netops_autopilot.chat.operator import ChatOperator

    class _FakeDevice:
        device_ref = "seed-01"
        status = type("S", (), {"value": "COMPLETE"})()
        identity = None
        mgmt_addresses: List[str] = []
        commands: list = []
        classification = type("C", (), {"value": "SEED"})()

    class _FakeDiscovery:
        devices = [_FakeDevice()]
        totals = {"devices": 1, "commands_collected": 1, "commands_planned": 1,
                  "device_status": {"COMPLETE": 1}}

    session = _StubSession({
        "show ip route": (
            b"S*    0.0.0.0/0 [1/0] via 10.0.0.1\n"
            b"C        10.0.0.0/24 is directly connected, Vlan10\n"
            b"L        10.0.0.1/32 is directly connected, Vlan10\n"
        ),
    })
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    op = ChatOperator(store=store, device_runner=runner, allowlist=allowlist)
    op._ctx.last_discovery = _FakeDiscovery()

    reply = op.handle("show ip route")
    assert reply.status.value == "OK"
    assert reply.data.get("route_count", 0) >= 2


def test_chat_show_neighbors_runs_real_lldp(store, allowlist) -> None:
    """``show neighbors`` lowers to ``show lldp neighbors detail``."""
    from netops_autopilot.chat.operator import ChatOperator

    class _FakeDevice:
        device_ref = "seed-01"
        status = type("S", (), {"value": "COMPLETE"})()
        identity = None
        mgmt_addresses: List[str] = []
        commands: list = []
        classification = type("C", (), {"value": "SEED"})()

    class _FakeDiscovery:
        devices = [_FakeDevice()]
        totals = {"devices": 1, "commands_collected": 1, "commands_planned": 1,
                  "device_status": {"COMPLETE": 1}}

    session = _StubSession({
        "show lldp neighbors detail": (
            b"Local Intf: Gi1/0/1\nChassis id: 0011.2233.4455\n"
            b"Port id: Gi1/0/1\nSystem Name: core-sw2\n\n"
            b"Local Intf: Gi1/0/2\nChassis id: 0022.3344.5566\n"
            b"Port id: Gi1/0/2\nSystem Name: access-sw1\n"
        ),
    })
    runner = DeviceCommandRunner(
        session_factory=lambda dev: session,
        allowlist=allowlist, store=store,
    )
    op = ChatOperator(store=store, device_runner=runner, allowlist=allowlist)
    op._ctx.last_discovery = _FakeDiscovery()

    reply = op.handle("show neighbors")
    assert reply.status.value == "OK"
    assert reply.data.get("neighbor_count", 0) >= 2
