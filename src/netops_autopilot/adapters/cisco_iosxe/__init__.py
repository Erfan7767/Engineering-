"""Cisco IOS/IOS-XE adapter — the first REAL hardware path (ADR-0001).

v1 scope, honest:
* ``AccessAdapter.open_session(method='serial_console')`` builds an
  ExecSession over :class:`SerialConsoleTransport` (pySerial, lazily
  imported; BLOCKED driver absence, never an ImportError crash);
* ``DiscoveryAdapter.run_layer`` maps D0-08 discovery layers to the
  family's READ_ONLY allowlist commands — a layer with no mapped command
  answers with a typed ``NOT_MODELED`` Failure (T2);
* ``ConfigAdapter.capture_running_config`` returns the allowlisted
  ``show running-config`` payload bytes for the Collector/baseline path;
* everything else inherits the typed ``NOT_SUPPORTED`` defaults of the
  interfaces — no stub pretends to work.
"""

from __future__ import annotations

from typing import Optional

from ...access.serial_transport import SerialConsoleTransport, SerialProfile
from ...core.failures import Failure, FailureClass
from ..interfaces import (
    AccessAdapter,
    CapabilityState,
    ConfigAdapter,
    DiscoveryAdapter,
    ExecSession,
)

#: D0-08 layer → allowlisted READ_ONLY command (cisco/ios-xe allowlist).
LAYER_COMMANDS: dict[str, str] = {
    "identity": "show version",
    "hardware": "show inventory",
    "l1_interface": "show interfaces status",
    "l2": "show vlan brief",
    "l2_mac": "show mac address-table",
    "neighbor": "show lldp neighbors detail",
    "neighbor_cdp": "show cdp neighbors detail",
    "l3": "show ip route",
    "config": "show running-config",
}


class CiscoIosXeSerialAdapter(AccessAdapter, DiscoveryAdapter, ConfigAdapter):
    """Session-bound Cisco adapter; one instance answers for IOS-XE family."""

    vendor_family = "cisco/ios-xe"

    def __init__(self, *, port_factory=None, clock=None, sleep=None) -> None:
        self._port_factory = port_factory
        self._clock = clock
        self._sleep = sleep
        self._sessions: dict[str, SerialConsoleTransport] = {}

    # ------------------------------------------------------------ capability
    def capability(self, operation: str) -> CapabilityState:
        if operation in ("open_session:serial_console", "capture_running_config") or \
                operation.startswith("discovery_layer:"):
            layer = operation.split(":", 1)[1] if ":" in operation else ""
            if operation == "capture_running_config" or operation == "open_session:serial_console":
                return CapabilityState.SUPPORTED
            return CapabilityState.SUPPORTED if layer in LAYER_COMMANDS else CapabilityState.NOT_SUPPORTED
        return CapabilityState.NOT_SUPPORTED

    # ------------------------------------------------------- access adapter
    def open_session(self, device_ref: str, method: str) -> ExecSession:
        if method != "serial_console":
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"NOT_SUPPORTED: open_session:{method} — v1 implements serial_console only (T2)",))
        profile = SerialProfile(port=device_ref)  # device_ref == COMx / /dev/tty*
        transport = SerialConsoleTransport(
            profile, port_factory=self._port_factory,
            clock=self._clock if self._clock else __import__("time").monotonic,
            sleep=self._sleep if self._sleep else __import__("time").sleep)
        transport.open()
        self._sessions[device_ref] = transport
        return transport

    def close_session(self, device_ref: str) -> None:
        transport = self._sessions.pop(device_ref, None)
        if transport is not None:
            transport.close()

    def acquire_lock(self, device_ref: str) -> bool:
        """Console attachment is exclusive by construction (one process owns
        the COM port); the Collector-level SessionLockManager is the real
        lock authority — this answers the transport-level truth."""
        return device_ref in self._sessions

    def release_lock(self, device_ref: str) -> None:
        return None

    def human_session_active(self, device_ref: str) -> bool:
        """The serial transport cannot prove exclusivity IF the operator
        attached elsewhere first; conservative default per interface law is
        overridden here ONLY by construction: WE hold the open port handle —
        no other process can hold it simultaneously on the same host."""
        return device_ref in self._sessions

    # --------------------------------------------------- discovery adapter
    def run_layer(self, device_ref: str, layer: str) -> bytes:
        command = LAYER_COMMANDS.get(layer)
        session = self._sessions.get(device_ref)
        if command is None or session is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"NOT_MODELED: discovery layer {layer!r} has no mapped command "
                f"or no open session for {device_ref!r} (T2)",))
        return session.execute(command, timeout_s=30.0)

    # ------------------------------------------------------ config adapter
    def capture_running_config(self, device_ref: str) -> bytes:
        session = self._sessions.get(device_ref)
        if session is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"SESSION_NOT_OPEN: capture_running_config requires open_session first",))
        return session.execute("show running-config", timeout_s=60.0)
