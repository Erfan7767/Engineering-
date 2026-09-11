"""Tests for the connection management subsystem."""

from __future__ import annotations

import time

import pytest

from netops_autopilot.access.connection import (
    ConnectionHealth,
    ConnectionMonitor,
    ConnectionState,
    DiscoveredPort,
    ProbeProfile,
    ProbeResult,
    RetryPolicy,
    connect_with_retry,
    list_serial_ports,
    probe_with_profiles,
)
from netops_autopilot.access.serial_transport import (
    SerialConsoleTransport,
    SerialProfile,
    SerialPortLike,
)
from netops_autopilot.core.failures import Failure, FailureClass


# ----------------- DiscoveredPort -----------------


def test_discovered_port_label_includes_device():
    p = DiscoveredPort(device="COM5", description="USB-Serial CH340")
    label = p.label()
    assert "COM5" in label
    assert "USB-Serial CH340" in label


def test_discovered_port_label_empty_description():
    p = DiscoveredPort(device="/dev/ttyUSB0")
    assert p.label() == "/dev/ttyUSB0"


# ----------------- list_serial_ports -----------------


def test_list_serial_ports_returns_list():
    out = list_serial_ports()
    assert isinstance(out, list)
    # Either pyserial is installed and returns ports, or it isn't and we
    # get []. Either way, never raise.


# ----------------- ProbeProfile -----------------


def test_probe_profile_rejects_bad_baud():
    with pytest.raises(ValueError):
        ProbeProfile(baud=0)


def test_probe_profile_accepts_positive_baud():
    p = ProbeProfile(baud=9600, label="default")
    assert p.baud == 9600
    assert p.label == "default"


# ----------------- RetryPolicy -----------------


def test_retry_policy_rejects_zero_attempts():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)


def test_retry_policy_rejects_zero_backoff():
    with pytest.raises(ValueError):
        RetryPolicy(initial_backoff_s=0)


def test_retry_policy_rejects_multiplier_less_than_1():
    with pytest.raises(ValueError):
        RetryPolicy(backoff_multiplier=0.5)


def test_backoff_grows_exponentially():
    p = RetryPolicy(max_attempts=5, initial_backoff_s=1.0, backoff_multiplier=2.0, jitter_s=0)
    assert p.backoff_for(0) == 0.0
    assert p.backoff_for(1) == 1.0
    assert p.backoff_for(2) == 2.0
    assert p.backoff_for(3) == 4.0
    assert p.backoff_for(4) == 8.0


def test_backoff_caps_at_max():
    p = RetryPolicy(max_attempts=10, initial_backoff_s=1.0, backoff_multiplier=2.0, max_backoff_s=5.0, jitter_s=0)
    assert p.backoff_for(5) == 5.0
    assert p.backoff_for(8) == 5.0


# ----------------- probe_with_profiles -----------------


def test_probe_no_profiles_returns_no_profiles_failure():
    out = probe_with_profiles([], port="COM99")
    assert out.success is False
    assert out.cause == "NO_PROFILES"


def test_probe_uses_first_successful_baud(monkeypatch):
    """Mock the transport so a specific baud always succeeds."""
    from netops_autopilot.access import connection as conn_mod

    class _GoodPort(SerialPortLike):
        def write(self, data: bytes) -> int:
            return len(data)
        def read(self, size: int = 1) -> bytes:
            return b"x"
        def reset_input_buffer(self) -> None:
            pass
        def close(self) -> None:
            pass

    monkeypatch.setattr(conn_mod.SerialConsoleTransport, "open", lambda self: setattr(self, "_port", _GoodPort()) or setattr(self, "_baud", self._profile.baud_candidates[0]))

    profiles = [ProbeProfile(baud=9600), ProbeProfile(baud=115200)]
    out = probe_with_profiles(profiles, port="COM5")
    assert out.success is True
    assert out.baud == 9600


# ----------------- connect_with_retry -----------------


def _make_failing_factory(failures_before_success: int):
    """A port factory that fails ``failures_before_success`` times then succeeds.

    The transport wraps generic exceptions into ``Failure(RETRYABLE)`` itself,
    but for this unit test we exercise the retry loop directly by raising
    :class:`Failure(RETRYABLE)` from the factory — which is what the serial
    transport does internally for transient I/O errors.
    """
    state = {"calls": 0}

    def factory(port: str, baud: int, read_timeout_s: float) -> SerialPortLike:
        state["calls"] += 1
        if state["calls"] <= failures_before_success:
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"transient I/O #{state['calls']}",),
                retry_hint="reconnect",
            )

        class _Port(SerialPortLike):
            def __init__(self):
                self._buffer = b"Router#\n"  # decodable banner
                self._consumed = False

            def write(self, data: bytes) -> int:
                # Real devices echo or move on after a write; here we just
                # prepare the buffer to be read on the next read.
                return len(data)
            def read(self, size: int = 1) -> bytes:
                # Return a decodable payload once. The probe loop wants
                # *some* printable bytes; one read is enough.
                if self._consumed:
                    return b""
                self._consumed = True
                return self._buffer
            def reset_input_buffer(self) -> None:
                # Real ports flush the read side; we keep the canned banner
                # available for the next read so the probe succeeds.
                self._consumed = False
            def close(self) -> None:
                pass
        return _Port()
    return factory, state


def test_connect_with_retry_succeeds_after_retries():
    factory, state = _make_failing_factory(failures_before_success=2)
    # Wrap to count actual transport.open() invocations on a single transport.
    call_log = []
    real_factory = factory
    def wrapped(port, baud, rt):
        call_log.append((port, baud))
        return real_factory(port, baud, rt)
    transport = connect_with_retry(
        SerialProfile(port="COM5", baud_candidates=(9600,)),
        retry_policy=RetryPolicy(max_attempts=5, initial_backoff_s=0.001, jitter_s=0),
        port_factory=wrapped,
        sleep=lambda _: None,  # no real sleep
    )
    assert state["calls"] == 3, f"expected 3 factory calls, got {state['calls']}; call_log={call_log}"
    transport.close()


def test_connect_with_retry_blocks_on_persistent_failure():
    factory, state = _make_failing_factory(failures_before_success=100)
    with pytest.raises(Failure) as exc:
        connect_with_retry(
            SerialProfile(port="COM5", baud_candidates=(9600,)),
            retry_policy=RetryPolicy(max_attempts=3, initial_backoff_s=0.001, jitter_s=0),
            port_factory=factory,
            sleep=lambda _: None,
        )
    assert exc.value.cls is FailureClass.BLOCKED
    assert "RETRY_EXHAUSTED" in exc.value.causes[-1]
    assert state["calls"] == 3


def test_connect_with_retry_does_not_retry_blocked():
    """BLOCKED failures (e.g., bad config) must NOT trigger retry."""
    from netops_autopilot.access import connection as conn_mod
    real = conn_mod.SerialConsoleTransport

    class _BlockedTransport(real):
        def open(self) -> None:
            raise Failure(cls=FailureClass.BLOCKED, causes=("BAD_BAUD: 0",))

    monkey = pytest.MonkeyPatch()
    monkey.setattr(conn_mod, "SerialConsoleTransport", _BlockedTransport)
    with pytest.raises(Failure) as exc:
        connect_with_retry(
            SerialProfile(port="COM5", baud_candidates=(9600,)),
            retry_policy=RetryPolicy(max_attempts=5, initial_backoff_s=0.001, jitter_s=0),
            sleep=lambda _: None,
        )
    # We must NOT see "RETRY_EXHAUSTED" since we don't retry BLOCKED.
    assert "BAD_BAUD" in exc.value.causes[0]
    assert not any("RETRY_EXHAUSTED" in c for c in exc.value.causes)
    monkey.undo()


# ----------------- ConnectionMonitor -----------------


def test_monitor_initial_state_disconnected():
    m = ConnectionMonitor()
    h = m.snapshot()
    assert h.state is ConnectionState.DISCONNECTED


def test_monitor_mark_negotiated_starts_clock():
    m = ConnectionMonitor()
    m.mark_negotiated("COM5", 9600)
    h = m.snapshot()
    assert h.state is ConnectionState.CONNECTED
    assert h.port == "COM5"
    assert h.baud == 9600
    assert h.negotiated_at is not None
    assert h.uptime_s >= 0


def test_monitor_command_updates_counters():
    m = ConnectionMonitor()
    m.mark_negotiated("COM5", 9600)
    m.mark_command(sent=10, received=200, ok=True)
    m.mark_command(sent=10, received=0, ok=False)
    h = m.snapshot()
    assert h.bytes_sent == 20
    assert h.bytes_received == 200
    assert h.command_count == 2
    assert h.error_count == 1


def test_monitor_degraded_after_3_errors():
    m = ConnectionMonitor()
    m.mark_negotiated("COM5", 9600)
    m.mark_command(sent=1, received=0, ok=False)
    m.mark_command(sent=1, received=0, ok=False)
    assert m.snapshot().state is ConnectionState.CONNECTED
    m.mark_command(sent=1, received=0, ok=False)
    assert m.snapshot().state is ConnectionState.DEGRADED


def test_monitor_disconnect_resets():
    m = ConnectionMonitor()
    m.mark_negotiated("COM5", 9600)
    m.mark_command(sent=10, received=10, ok=True)
    m.mark_disconnected()
    h = m.snapshot()
    assert h.state is ConnectionState.DISCONNECTED


def test_monitor_failed_carries_cause():
    m = ConnectionMonitor()
    m.mark_failed("NO_BAUD_RESPONSE")
    h = m.snapshot()
    assert h.state is ConnectionState.FAILED
    assert h.last_error == "NO_BAUD_RESPONSE"


def test_health_to_dict():
    h = ConnectionHealth(state=ConnectionState.CONNECTED, port="COM5", baud=9600)
    d = h.to_dict()
    assert d["state"] == "CONNECTED"
    assert d["port"] == "COM5"
    assert d["baud"] == 9600
