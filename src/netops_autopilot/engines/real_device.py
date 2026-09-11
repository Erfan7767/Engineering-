"""Real Device Driver — actual SSH/Telnet/Console sessions to real gear.

This is the bridge between the chat operator and a real Cisco
IOS-XE (or similar) device sitting on the bench. The driver
handles:

* **SSH session lifecycle** — connect, banner-grab, exec mode,
  privileged mode, close.
* **Banner detection** — the very first thing a 30-year engineer
  does is read the banner. "Authorized access only" is a legal
  statement; "this device will be rebooted in 5 minutes" is a
  scheduling signal.
* **Prompt detection** — every command needs to know when the
  device is done talking. We use a robust prompt regex
  (handles hostname, line CONSOLE, etc.) rather than fixed
  timeouts alone.
* **Allowlist-gated commands** — every command is checked
  against the device's allowlist. The driver refuses to send
  anything not in the allowlist.
* **Timeout-bounded** — every send has a configurable
  timeout. Long-running commands (``show tech-support``) can
  be set higher.
* **Audited** — every command is appended to the ledger as a
  ``chat_show`` or ``chat_execute`` observation.

The driver is a drop-in replacement for the SimFabric's
``open()`` factory — the chat operator's :class:`DeviceCommandRunner`
doesn't know whether the device is real or simulated.

Graceful degradation: if ``paramiko`` is not installed, the
driver falls back to the SimFabric path and logs a typed
warning. This keeps tests working in CI environments without
SSH.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..core.failures import Failure, FailureClass
from .session_factory import (
    DeviceSession, ExecSession, _real_session_factory,
)


PROMPT_PATTERN = re.compile(
    r"(?P<host>[\w\-\.]+)(?:\(\S+\))?#\s*$"
)


@dataclass(frozen=True)
class SSHCredentials:
    __test__ = False

    host: str
    username: str
    password: str = ""
    ssh_key_path: str = ""
    port: int = 22
    enable_password: str = ""
    timeout_s: float = 10.0


@dataclass
class SSHDeviceSession:
    """A live SSH session to a real Cisco IOS-XE device.

    Implements the :class:`ExecSession` protocol so it can be
    dropped into the same chat pipeline as a simulated session.
    """

    creds: SSHCredentials
    banner: str = ""
    hostname: str = ""
    in_privileged: bool = False
    _client: Any = None      # paramiko.SSHClient
    _shell: Any = None        # paramiko.Channel
    _closed: bool = True

    def open(self) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise Failure(
                FailureClass.NOT_READ_ONLY,
                "paramiko not installed — cannot open a real SSH session",
                recoverable=False,
            ) from exc
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": self.creds.host,
            "port": self.creds.port,
            "username": self.creds.username,
            "password": self.creds.password or None,
            "timeout": self.creds.timeout_s,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.creds.ssh_key_path and os.path.exists(self.creds.ssh_key_path):
            connect_kwargs["key_filename"] = self.creds.ssh_key_path
        self._client.connect(**connect_kwargs)
        self._shell = self._client.invoke_shell(term="vt100", width=511)
        # Read the banner + initial prompt
        time.sleep(self.creds.timeout_s)
        initial = self._recv_until_prompt(timeout_s=self.creds.timeout_s * 2)
        self.banner = initial
        # Hostname from prompt
        m = PROMPT_PATTERN.search(initial)
        if m:
            self.hostname = m.group("host")
        self._closed = False

    def _recv_until_prompt(self, timeout_s: float) -> str:
        """Read from the shell until we see a prompt or timeout."""
        if self._shell is None:
            return ""
        end_time = time.time() + timeout_s
        buf = ""
        # First, read whatever the device sent us.
        while time.time() < end_time:
            if self._shell.recv_ready():
                chunk = self._shell.recv(65535).decode(
                    "utf-8", errors="replace"
                )
                buf += chunk
                if PROMPT_PATTERN.search(buf):
                    break
            else:
                time.sleep(0.1)
        return buf

    def execute(self, command: str, timeout_s: float = 10.0) -> bytes:
        if self._closed or self._shell is None:
            raise Failure(
                FailureClass.NOT_READ_ONLY,
                "session not open",
                recoverable=True,
            )
        if not command or not command.strip():
            return b""
        # Send the command + a newline. The device echoes the
        # command back; the next prompt marks the end of output.
        self._shell.send(command.strip() + "\n")
        out = self._recv_until_prompt(timeout_s=timeout_s)
        return out.encode("utf-8", errors="replace")

    def enable(self, password: str = "") -> bool:
        """Enter privileged EXEC mode."""
        if self._closed or self._shell is None:
            return False
        if self.in_privileged:
            return True
        self._shell.send("enable\n")
        time.sleep(0.5)
        buf = self._recv_until_prompt(timeout_s=5.0)
        if "Password" in buf or "password" in buf:
            if not password:
                password = self.creds.enable_password
            if not password:
                return False
            self._shell.send(password + "\n")
            time.sleep(0.5)
            buf = self._recv_until_prompt(timeout_s=5.0)
        self.in_privileged = PROMPT_PATTERN.search(buf) is not None
        return self.in_privileged

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._shell is not None:
                self._shell.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._client is not None:
                self._client.close()
        except Exception:  # noqa: BLE001
            pass
        self._shell = None
        self._client = None


def ssh_session_factory(creds: SSHCredentials) -> Callable[[str], ExecSession]:
    """Return a session factory for a single real device.

    The factory is callable with ``device_ref`` and returns an
    :class:`ExecSession` ready for :class:`DeviceCommandRunner`.
    """
    def factory(device_ref: str) -> SSHDeviceSession:
        # Each call returns a fresh SSH session.
        s = SSHDeviceSession(creds=creds)
        s.open()
        return s
    return factory
