"""DeviceCommandRunner — actually executes read-only commands on a real device.

The chat operator can now call ``device.run_show("seed-01", "show ip route")``
and get back the real bytes from the real device. This is what makes
``ping``, ``traceroute``, ``show ip route``, ``show neighbors``, etc.
work end-to-end in the chat — not stubs.

Design:

* **Reuses the session factory** the AutopilotEngine used during
  discovery. The factory is closed after discovery, so the runner
  takes a *device* (an inventory record) and re-opens a fresh
  session through the same factory on each call.
* **Allowlist-gated**: only READ_ONLY templates from the active
  vendor's allowlist may run. Anything else raises Failure (L10/T3).
* **Timeout-bounded**: every call has a 30s default. Configurable
  per-call.
* **Audited**: every command appends a ``chat_show`` observation to
  the ledger so the audit trail is complete.
* **Real evidence**: the returned ``DeviceCommandResult`` carries
  the raw output, the exit-time, the device ref, the command, and
  whether the output was non-empty (i.e. the device actually
  responded).

The runner is the key to the "no hallucination" rule: every chat
output that the user sees for a ``show *`` command is the real
device output, possibly with a short title for context.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from ..access.allowlist import CommandAllowlist
from ..core.failures import Failure, FailureClass
from ..ledger.models import (
    CollectorIdentity,
    Event,
    EventSignature,
    EventType,
    OperatorIdentity,
    ParseStatus,
    Observation,
)
from ..ledger.store import LedgerStore


class _ExecSession(Protocol):
    """The shape we need from a device session — minimal."""

    def execute(self, command: str, timeout_s: float) -> bytes: ...
    def close(self) -> None: ...


class _SessionFactory(Protocol):
    """A callable that returns a fresh session for a device.

    ``open(device_ref)`` opens a NEW management session to the
    given device and returns an object with an ``execute`` method.
    The session is closed by the runner after the command returns.
    """

    def __call__(self, device_ref: str) -> _ExecSession: ...


@dataclass
class DeviceCommandResult:
    """The real output of a real command on a real device.

    Carries everything the chat operator (and the UI) needs to
    render the result honestly: the raw bytes, the device ref,
    the command, the elapsed time, and a typed ``success`` flag.
    """

    device_ref: str
    command: str
    output: bytes
    elapsed_s: float
    success: bool
    note: str = ""

    @property
    def output_text(self) -> str:
        try:
            return self.output.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return self.output.decode("latin-1", errors="replace")

    def to_dict(self) -> dict:
        return {
            "device_ref": self.device_ref,
            "command": self.command,
            "output": self.output_text,
            "elapsed_s": round(self.elapsed_s, 3),
            "success": self.success,
            "note": self.note,
        }


class DeviceCommandRunner:
    """Runs READ_ONLY commands on real devices.

    The chat operator can hold a reference to one of these. The
    runner is created with:

    * ``session_factory``: an open-session callable (the same factory
      the autopilot used, or a sim-fabric for tests).
    * ``allowlist``: the loaded vendor allowlist (READ_ONLY gate).
    * ``store``: the ledger (audit trail).
    * ``timeout_s``: default per-command timeout.

    The runner does NOT cache sessions. Every call opens a fresh
    session, runs exactly one command, and closes. This keeps
    state simple and matches how real serial/SSH sessions work
    (you reconnect for every operation).
    """

    # Cisco IOS-XE ping — works on the seed device. The chat's
    # ``ping <ip>`` command lowers to this on the device.
    PING_REPEAT = "ping {target} repeat 5"
    TRACEROUTE_CMD = "traceroute {target}"

    def __init__(
        self,
        *,
        session_factory: _SessionFactory,
        allowlist: CommandAllowlist,
        store: LedgerStore,
        default_timeout_s: float = 30.0,
    ) -> None:
        self._open = session_factory
        self._allowlist = allowlist
        self._store = store
        self._timeout = default_timeout_s

    # ---- public API ------------------------------------------------------

    def run_show(
        self,
        device_ref: str,
        command: str,
        *,
        timeout_s: Optional[float] = None,
    ) -> DeviceCommandResult:
        """Execute a read-only show command on a device.

        Raises :class:`Failure` with class ``CONFIG_*`` if the
        command isn't in the READ_ONLY allowlist. Returns a
        :class:`DeviceCommandResult` on success or transport failure
        (``success=False`` is set, never raises, for connection /
        timeout errors — these are part of the honest picture).
        """
        self._ensure_read_only(command)
        return self._execute(device_ref, command, timeout_s or self._timeout)

    def ping(self, device_ref: str, target: str) -> DeviceCommandResult:
        """Execute ``ping <target>`` on the device.

        The chat's ``ping <ip>`` lowers to the device's own ping
        (not the host's), so the result reflects the device's view
        of reachability — which is what a network engineer cares
        about.
        """
        if not self._is_valid_target(target):
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"INVALID_PING_TARGET: {target!r} not a valid IP or hostname",),
            )
        self._ensure_read_only("ping")
        cmd = self.PING_REPEAT.format(target=target)
        return self._execute(device_ref, cmd, self._timeout)

    def traceroute(self, device_ref: str, target: str) -> DeviceCommandResult:
        """Execute ``traceroute <target>`` on the device."""
        if not self._is_valid_target(target):
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"INVALID_TRACEROUTE_TARGET: {target!r}",),
            )
        self._ensure_read_only("traceroute")
        cmd = self.TRACEROUTE_CMD.format(target=target)
        return self._execute(device_ref, cmd, self._timeout)

    def is_alive(self, device_ref: str) -> bool:
        """Quick reachability check (executes ``show clock``)."""
        self._ensure_read_only("show clock detail")
        r = self._execute(device_ref, "show clock detail", 10.0)
        return r.success and bool(r.output.strip())

    @property
    def session_factory(self):
        """Public access to the session factory (used by the chat
        operator for write operations like ``rollback``)."""
        return self._open

    def open_session(self, device_ref: str):
        """Open a fresh session for the device. Caller is responsible
        for closing it (use the result as a context manager or call
        ``.close()`` explicitly)."""
        return self._open(device_ref)

    # ---- internals -------------------------------------------------------

    def _ensure_read_only(self, template_prefix: str) -> None:
        """Refuse anything that isn't a READ_ONLY allowlist entry.

        We allow either an exact template match (e.g. ``show ip route``)
        or a template *prefix* match (e.g. ``ping`` matches
        ``ping <target> repeat 5``). For prefix matches we still
        require the prefix to be in the allowlist; otherwise we
        refuse.
        """
        cls = self._classify_with_prefix(template_prefix)
        if cls != "READ_ONLY":
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(
                    f"NOT_READ_ONLY: {template_prefix!r} is class "
                    f"{cls or 'UNKNOWN'} — chat may only run READ_ONLY commands "
                    f"(L10/T3).",
                ),
            )

    def _classify_with_prefix(self, command: str) -> str | None:
        """Match ``ping <args>`` against the ``ping`` allowlist entry.

        The base ``CommandAllowlist.classify`` only does exact match.
        We extend it here so the chat can run ``ping 10.0.0.1`` and
        have it classified under the ``ping`` template. The match
        is anchored on the first word of the command.
        """
        direct = self._allowlist.classify(command)
        if direct:
            return direct
        # Try the first word (e.g. "ping" out of "ping 10.0.0.1 repeat 5").
        head = command.strip().split(None, 1)[0] if command.strip() else ""
        if head:
            head_cls = self._allowlist.classify(head)
            if head_cls:
                return head_cls
        return None

    def _execute(
        self, device_ref: str, command: str, timeout_s: float,
    ) -> DeviceCommandResult:
        t0 = time.monotonic()
        session = None
        try:
            session = self._open(device_ref)
        except Exception as exc:  # noqa: BLE001
            r = DeviceCommandResult(
                device_ref=device_ref, command=command, output=b"",
                elapsed_s=time.monotonic() - t0, success=False,
                note=f"open_session failed: {exc!r}",
            )
            self._audit(device_ref, command, r)
            return r
        try:
            try:
                output = session.execute(command, timeout_s)
            except (TimeoutError, ConnectionError, OSError) as exc:
                r = DeviceCommandResult(
                    device_ref=device_ref, command=command, output=b"",
                    elapsed_s=time.monotonic() - t0, success=False,
                    note=f"{type(exc).__name__}: {exc}",
                )
                self._audit(device_ref, command, r)
                return r
            r = DeviceCommandResult(
                device_ref=device_ref, command=command, output=output,
                elapsed_s=time.monotonic() - t0,
                success=bool(output and output.strip()),
            )
            self._audit(device_ref, command, r)
            return r
        finally:
            try:
                if session is not None:
                    session.close()
            except Exception:  # noqa: BLE001
                pass

    def _audit(
        self, device_ref: str, command: str, result: DeviceCommandResult,
    ) -> None:
        """Append a chat_show observation to the ledger.

        The audit is best-effort and NEVER blocks the user.
        """
        try:
            self._store.append_observation(Observation(
                obs_id=f"chat-show-{int(time.time() * 1000)}",
                raw_id=f"chat-show:{device_ref}:{command[:30]}",
                parser_id="device_command_runner/0.1.0",
                parser_version="0.1.0",
                field="chat_show",
                value=command,
                parse_status=(ParseStatus.OK if result.success
                              else ParseStatus.UNPARSED),
            ))
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _is_valid_target(target: str) -> bool:
        """An IP address or a simple hostname."""
        if not target:
            return False
        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return True
        # Hostname
        if re.match(r"^[a-zA-Z][a-zA-Z0-9\-_.]{1,253}$", target):
            return True
        return False
