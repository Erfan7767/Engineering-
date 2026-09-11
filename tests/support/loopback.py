"""Test doubles implementing the adapter interfaces (D1 test infra).

LoopbackSession/LoopbackAccessAdapter are NOT vendor adapters; they exist so
the Collector and engines are exercised against the real interface contracts
before lab-hardware adapters land (ADR-0006 tiers run on hardware later).
"""

from __future__ import annotations

from netops_autopilot.adapters.interfaces import AccessAdapter, CapabilityState, ExecSession


class LoopbackSession:
    """Canned responses keyed by command; supports fault injection.

    The session tracks every command it has received in ``self.executed``,
    so the executor's actual write commands show up in the audit trail.
    Write commands (anything not in ``outputs``) return a generic
    success response and are recorded in ``self.written_config``.
    """

    TIMEOUT_SENTINEL = "__TIMEOUT__"
    CONNFAIL_SENTINEL = "__CONNFAIL__"

    def __init__(self, outputs: dict[str, bytes] | None = None, fail_times: dict[str, int] | None = None) -> None:
        self.outputs = dict(outputs or {})
        self.fail_times = dict(fail_times or {})
        self.executed: list[str] = []
        self.written_config: list[str] = []
        self.closed = False
        self.started_in_config_mode: bool = False

    def execute(self, command: str, timeout_s: float) -> bytes:
        self.executed.append(command)
        if self.fail_times.get(command, 0) > 0:
            self.fail_times[command] -= 1
            raise ConnectionError("loopback injected transport failure")
        out = self.outputs.get(command, b"")
        if not out:
            # Try prefix match: ``ping 10.0.0.1 repeat 5`` → ``ping``
            head = command.strip().split(None, 1)[0] if command.strip() else ""
            if head and head in self.outputs:
                out = self.outputs[head]
        if not out:
            # Try "ping <ip>" / "traceroute <ip>" without repeat count.
            cmd_stripped = command.strip()
            parts = cmd_stripped.split()
            if len(parts) == 2 and parts[0].lower() in ("ping", "traceroute"):
                # If we have a canned response for that verb, return it.
                verb = parts[0].lower()
                if verb in self.outputs:
                    out = self.outputs[verb]
        if out == self.TIMEOUT_SENTINEL.encode():
            raise TimeoutError("loopback injected timeout")
        if out == self.CONNFAIL_SENTINEL.encode():
            raise ConnectionError("loopback injected connection failure")
        # If the command is a write (not in the read-only canned
        # outputs), record it as actually written and return a
        # generic success response. This is what a real device would
        # do for any well-formed config line.
        if not out:
            cmd_stripped = command.strip()
            head = cmd_stripped.split(None, 1)[0] if cmd_stripped else ""
            # ``show running-config`` returns the current
            # running-config (built from written_config). This is
            # the executor's post-apply verification hook.
            if cmd_stripped == "show running-config":
                return self.running_config().encode("utf-8")
            READ_HEADS = {"show", "ping", "traceroute"}
            if head and head.lower() not in READ_HEADS and not cmd_stripped.startswith("!"):
                self.written_config.append(cmd_stripped)
                # Transition tracking
                if head.lower() in ("configure", "conf"):
                    self.started_in_config_mode = True
                elif cmd_stripped.lower() == "end":
                    self.started_in_config_mode = False
                # Standard Cisco IOS-XE success response
                return b""
        return out

    def close(self) -> None:
        self.closed = True

    def running_config(self) -> str:
        """Return the running-config as a Cisco-style text blob.

        Built from the lines that were written. This is what a real
        ``show running-config`` would return after the changes were
        applied.
        """
        lines = [
            "! Last applied by NetOps Autopilot",
            f"! {len(self.written_config)} command(s) committed",
            "!",
        ]
        lines.extend(self.written_config)
        return "\n".join(lines) + "\n"


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
