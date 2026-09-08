"""Test doubles implementing the adapter interfaces (D1 test infra).

LoopbackSession/LoopbackAccessAdapter are NOT vendor adapters; they exist so
the Collector and engines are exercised against the real interface contracts
before lab-hardware adapters land (ADR-0006 tiers run on hardware later).
"""

from __future__ import annotations

from netops_autopilot.adapters.interfaces import AccessAdapter, CapabilityState, ExecSession


class LoopbackSession:
    """Canned responses keyed by command; supports fault injection."""

    TIMEOUT_SENTINEL = "__TIMEOUT__"
    CONNFAIL_SENTINEL = "__CONNFAIL__"

    def __init__(self, outputs: dict[str, bytes] | None = None, fail_times: dict[str, int] | None = None) -> None:
        self.outputs = dict(outputs or {})
        self.fail_times = dict(fail_times or {})
        self.executed: list[str] = []
        self.closed = False

    def execute(self, command: str, timeout_s: float) -> bytes:
        self.executed.append(command)
        if self.fail_times.get(command, 0) > 0:
            self.fail_times[command] -= 1
            raise ConnectionError("loopback injected transport failure")
        out = self.outputs.get(command, b"")
        if out == self.TIMEOUT_SENTINEL.encode():
            raise TimeoutError("loopback injected timeout")
        if out == self.CONNFAIL_SENTINEL.encode():
            raise ConnectionError("loopback injected connection failure")
        return out

    def close(self) -> None:
        self.closed = True


class LoopbackAccessAdapter(AccessAdapter):
    """Minimal AccessAdapter over LoopbackSession for pipeline tests."""

    vendor_family = "test/loopback"

    def __init__(self, session: LoopbackSession) -> None:
        self._session = session
        self._locks: set[str] = set()

    def capability(self, operation: str) -> CapabilityState:
        return CapabilityState.SUPPORTED if operation.startswith("open_session") else CapabilityState.NOT_SUPPORTED

    def open_session(self, device_ref: str, method: str) -> ExecSession:
        return self._session

    def close_session(self, device_ref: str) -> None:
        self._session.close()

    def acquire_lock(self, device_ref: str) -> bool:
        if device_ref in self._locks:
            return False
        self._locks.add(device_ref)
        return True

    def release_lock(self, device_ref: str) -> None:
        self._locks.discard(device_ref)

    def human_session_active(self, device_ref: str) -> bool:
        return False  # loopback transport proves exclusivity
