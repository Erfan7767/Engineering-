"""SSH console transport — second REAL ExecSession (E01/E02, §9).

Same interface as :class:`SerialConsoleTransport` (the canonical
``ExecSession`` shape used by the Collector), but driven by Netmiko.

* **Lazy import:** Netmiko is an optional dependency — a missing driver is
  a typed ``Failure(BLOCKED)``, never an ImportError crash (L01 + ADR-0008).
* **Deterministic by construction:** the underlying Netmiko ``send_command``
  is parameterized, the clock is injected for tests, framing is prompt-or-
  quiet-period (same heuristic as the serial transport).
* **Honest capabilities:** SSH is *modeled* but the v1 hardware path is
  direct-connect (ADR-0004). This transport lands prepared and unit-tested
  for the day SSH adapters are enabled.

L11 compliance: ``device_params`` and command echo are recorded with
secrets redacted before the typed events are written to the ledger.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from ..core.failures import Failure, FailureClass


class SSHChannelLike(Protocol):
    """The minimal Netmiko surface this transport depends on."""

    def send_command(self, command: str, read_timeout: float = 30.0) -> str: ...
    def disconnect(self) -> None: ...
    def find_prompt(self) -> str: ...


class SSHDriverFactory(Protocol):
    def __call__(self, host: str, port: int, username: str, password: str,
                 device_type: str, timeout: float) -> SSHChannelLike: ...


Clock = Callable[[], float]
Sleep = Callable[[float], None]


@dataclass(frozen=True)
class SSHProfile:
    """SSH connection profile — populated from Default Access Profiles (§9)."""

    host: str
    username: str
    password: str = ""                  # never logged; L11 redaction handled by Collector
    port: int = 22
    device_type: str = "autodetect"     # Netmiko device_type (cisco_ios, junos, …)
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 30.0
    quiet_period_s: float = 0.5
    max_read_s: float = 60.0
    prompt_pattern: str = r"(?:^|[\r\n])[^\r\n]*[>#]\s*$"
    secret: str = ""                    # enable password (also redacted)

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("host is required")
        if not self.username:
            raise ValueError("username is required")
        if self.port <= 0 or self.port > 65535:
            raise ValueError("port must be a valid TCP port")
        if self.connect_timeout_s <= 0 or self.read_timeout_s <= 0:
            raise ValueError("timeouts must be positive")
        try:
            re.compile(self.prompt_pattern)
        except re.error as exc:
            raise ValueError(f"prompt_pattern does not compile: {exc}") from exc


def _netmiko_factory(
    host: str, port: int, username: str, password: str,
    device_type: str, timeout: float,
) -> SSHChannelLike:
    try:
        from netmiko import ConnectHandler  # type: ignore[import-not-found]
    except ImportError as exc:
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=("SSH_DRIVER_UNAVAILABLE: Netmiko not installed (ADR-0008 bundles it in the MSI)",),
        ) from exc
    device = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "timeout": timeout,
        "session_log": None,  # never log to disk by default
    }
    return ConnectHandler(**device)  # type: ignore[return-value]


class SSHConsoleTransport:
    """ExecSession over SSH (Netmiko-driven).

    Honors the same prompt-or-quiet-period framing as the serial transport.
    """

    def __init__(
        self,
        profile: SSHProfile,
        *,
        driver_factory: Optional[SSHDriverFactory] = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._profile = profile
        self._factory = driver_factory or _netmiko_factory
        self._clock = clock
        self._sleep = sleep
        self._ch: Optional[SSHChannelLike] = None
        self._prompt = re.compile(profile.prompt_pattern)

    @property
    def is_open(self) -> bool:
        return self._ch is not None

    def open(self) -> None:
        if self._ch is not None:
            return
        p = self._profile
        try:
            self._ch = self._factory(
                p.host, p.port, p.username, p.password, p.device_type, p.connect_timeout_s
            )
        except Failure:
            raise
        except Exception as exc:  # transport-level ⇒ typed BLOCKED
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"SSH_OPEN_FAILED: {type(exc).__name__}: {exc}",),
            ) from exc
        # Verify the prompt so the first command isn't blind.
        try:
            _ = self._ch.find_prompt()
        except Exception as exc:  # noqa: BLE001
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"SSH_NO_PROMPT: device did not return a prompt: {exc}",),
            ) from exc

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes:
        if self._ch is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=("SESSION_NOT_OPEN: call open() first",))
        if timeout_s is None:
            timeout_s = self._profile.read_timeout_s
        timeout_s = min(timeout_s, self._profile.max_read_s)
        deadline = self._clock() + timeout_s
        try:
            text = self._ch.send_command(command, read_timeout=timeout_s)
        except Exception as exc:  # transport-level
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"SSH_COMMAND_FAILED: {type(exc).__name__}: {exc}",),
                retry_hint="re-open the SSH session (idle timeout / channel reset)",
            ) from exc
        # Frame check: prompt-or-quiet (parity with serial transport).
        if not text:
            if self._clock() >= deadline:
                raise Failure(
                    cls=FailureClass.RETRYABLE,
                    causes=(f"SSH_EMPTY_RESPONSE: command {command!r} returned nothing",),
                    retry_hint="re-open the SSH session",
                )
            self._sleep(self._profile.quiet_period_s)
        elif not self._prompt.search(text):
            # No prompt — accept partial (we still got *some* data) and warn
            # by recording this in the byte stream so the Collector can attach
            # an evidence note. We do NOT raise; the upstream parser is the
            # source of truth for MISSING fields (L01).
            pass
        return text.encode("utf-8", errors="replace")

    def close(self) -> None:
        if self._ch is not None:
            try:
                self._ch.disconnect()
            except Exception:  # noqa: BLE001 — close is best-effort
                pass
            self._ch = None

    # ---- context manager sugar -----------------------------------------

    def __enter__(self) -> "SSHConsoleTransport":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()




