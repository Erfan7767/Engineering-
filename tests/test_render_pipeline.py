"""End-to-end tests for the access/adapter pipeline.

The current architecture is session-bound (L08 / ADR-0001): adapters
read evidence from a real (or simulated) device, never from a free-form
command list. These tests prove that the cisco_iosxe adapter:

* Answers layer queries with allowlisted read-only commands.
* Refuses to apply IR (Intent Realization) without an explicit allowlist
  (T3 / L04 — the free-form text is quarantined, not executed).
* Returns a typed NOT_MODELED failure for unmapped discovery layers.
* Closes the session cleanly on a normal teardown.
* Hands back the running-config bytes for the collector path.
"""

from __future__ import annotations

import pytest

from netops_autopilot.adapters.cisco_iosxe import (
    CiscoIosXeSerialAdapter,
    LAYER_COMMANDS,
)
from netops_autopilot.adapters.interfaces import CapabilityState
from netops_autopilot.core.failures import Failure, FailureClass


class _FakePort:
    """Minimal stand-in for a serial.Serial — returns canned bytes.

    Behaves like a real device banner + prompt response: the first
    read returns the banner; every subsequent read returns the
    prompt line so the framing loop breaks on the prompt match.
    """

    def __init__(self, banner: bytes, prompt: bytes = b"\nSW1#\n") -> None:
        self._banner = banner
        self._prompt = prompt
        self._phase = 0
        self.written: list[bytes] = []
        self.closed = False

    def reset_input_buffer(self):
        # Re-arm the read (matches real serial port: flush doesn't
        # destroy the next-read payload).
        self._phase = 0

    def reset_output_buffer(self):
        pass

    def write(self, data: bytes) -> int:
        self.written.append(data)
        return len(data)

    def read(self, size: int = 1) -> bytes:
        if self._phase == 0:
            self._phase = 1
            return self._banner
        return self._prompt

    def close(self):
        self.closed = True


def _open_adapter(port_name: str = "SIM0") -> CiscoIosXeSerialAdapter:
    port = _FakePort(b"\nSW1#\n")
    # Inject fake clock + no-op sleep so tests don't burn real wall time.
    fake_t = [0.0]
    def clock():
        fake_t[0] += 0.06  # advance 60ms each call (matches the read slice)
        return fake_t[0]
    adapter = CiscoIosXeSerialAdapter(
        port_factory=lambda p, b, t: port,
        clock=clock,
        sleep=lambda _s: None,
    )
    adapter.open_session(device_ref=port_name, method="serial_console")
    return adapter


# ----------------- Layer mapping -----------------


def test_layer_commands_table_is_complete():
    for layer in ("identity", "l1_interface", "l2", "l3", "neighbor", "config"):
        assert layer in LAYER_COMMANDS, f"missing layer: {layer}"


def test_layer_commands_are_read_only():
    """Every entry in LAYER_COMMANDS must start with 'show ' (L04 / T3)."""
    for layer, cmd in LAYER_COMMANDS.items():
        assert cmd.startswith("show "), f"layer {layer!r} maps to {cmd!r}, not read-only"


@pytest.mark.parametrize("layer, expected", [
    ("identity", "show version"),
    ("l2", "show vlan brief"),
    ("l3", "show ip route"),
    ("config", "show running-config"),
])
def test_layer_command_resolves_correctly(layer: str, expected: str):
    assert LAYER_COMMANDS[layer] == expected


# ----------------- Adapter session lifecycle -----------------


def test_adapter_opens_session_and_returns_exec():
    a = _open_adapter()
    assert a.human_session_active("SIM0") is True
    a.close_session("SIM0")
    assert a.human_session_active("SIM0") is False


def test_adapter_run_layer_for_known_layer_succeeds():
    a = _open_adapter()
    payload = a.run_layer(device_ref="SIM0", layer="identity")
    assert isinstance(payload, bytes)
    a.close_session("SIM0")


def test_adapter_run_layer_for_unknown_layer_returns_not_modeled():
    a = _open_adapter()
    with pytest.raises(Failure) as exc:
        a.run_layer(device_ref="SIM0", layer="layer-that-doesnt-exist")
    # The adapter must surface a typed failure, not crash.
    assert exc.value.cls is FailureClass.BLOCKED
    assert "NOT_MODELED" in exc.value.causes[0]
    a.close_session("SIM0")


def test_adapter_capture_running_config_returns_bytes():
    a = _open_adapter()
    cfg = a.capture_running_config(device_ref="SIM0")
    assert isinstance(cfg, bytes)
    a.close_session("SIM0")


# ----------------- IR application is guarded -----------------


def test_apply_ir_without_allowlist_is_blocked():
    a = _open_adapter()
    # The intent realization (free-form command text) must be
    # rejected without an explicit allowlist grant (T3).
    with pytest.raises(Failure) as exc:
        a.apply_ir(device_ref="SIM0", ir_ref="free-form-cmd-text", dry_run=True)
    assert exc.value.cls is FailureClass.BLOCKED
    a.close_session("SIM0")


# ----------------- Capability reporting -----------------


def test_capability_state_is_queryable():
    a = _open_adapter()
    cap = a.capability("run_layer")
    assert cap in (CapabilityState.SUPPORTED, CapabilityState.UNKNOWN,
                   CapabilityState.NOT_SUPPORTED)
    a.close_session("SIM0")


# ----------------- Adapter unknown method -----------------


def test_open_session_unknown_method_is_blocked():
    port = _FakePort(b"\nSW1#\n")
    a = CiscoIosXeSerialAdapter(port_factory=lambda p, b, t: port)
    with pytest.raises(Failure) as exc:
        a.open_session(device_ref="SIM0", method="ssh")
    assert exc.value.cls is FailureClass.BLOCKED
    assert "NOT_SUPPORTED" in exc.value.causes[0]
