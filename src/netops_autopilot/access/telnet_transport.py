"""Telnet console transport — third REAL ExecSession (E01/E02, §9).

Same interface as :class:`SerialConsoleTransport` and
:class:`SSHConsoleTransport`, but for legacy devices that only speak telnet.

* **Lazy import:** stdlib ``telnetlib`` is part of the standard library on
  Python ≤ 3.12, but removed in 3.13+ (PEP 594). A missing ``telnetlib`` is
  a typed ``Failure(BLOCKED)``, never an ImportError crash.
* **Honest capabilities:** like SSH, telnet is *modeled* in v1; the v1
  hardware path is direct-connect (ADR-0004). This module lands prepared
  and unit-tested for when telnet adapters are enabled.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from ..core.failures import Failure, FailureClass


class TelnetChannelLike(Protocol):
    """The minimal telnetlib surface this transport depends on."""

    def read_until(self, match: bytes | str, timeout: float | None = None) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class TelnetDriverFactory(Protocol):
    def __call__(self, host: str, port: int, timeout: float) -> TelnetChannelLike: ...


Clock = Callable[[], float]
Sleep = Callable[[float], None]


@dataclass(frozen=True)
class TelnetProfile:
    """Telnet connection profile."""

    host: str
    username: str
    password: str = ""           # redacted before reaching the ledger
    port: int = 23
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 30.0
    quiet_period_s: float = 0.5
    max_read_s: float = 60.0
    login_prompt: bytes = b"login:"
    password_prompt: bytes = b"Password:"
    prompt_pattern: str = r"(?:^|[\r\n])[^\r\n]*[>#]\s*$"
    enable_secret: str = ""      # also redacted

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


def _stdlib_telnet_factory(host: str, port: int, timeout: float) -> TelnetChannelLike:
    try:
        import telnetlib  # type: ignore[import-not-found]
    except ImportError as exc:
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=("TELNET_DRIVER_UNAVAILABLE: telnetlib not available in this Python (PEP 594; removed in 3.13+)",),
        ) from exc
    return telnetlib.Telnet(host=host, port=port, timeout=timeout)  # type: ignore[return-value]


class TelnetConsoleTransport:
    """ExecSession over telnet (stdlib ``telnetlib``-driven)."""

    def __init__(
        self,
        profile: TelnetProfile,
        *,
        driver_factory: Optional[TelnetDriverFactory] = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._profile = profile
        self._factory = driver_factory or _stdlib_telnet_factory
        self._clock = clock
        self._sleep = sleep
        self._ch: Optional[TelnetChannelLike] = None
        self._prompt = re.compile(profile.prompt_pattern)

    @property
    def is_open(self) -> bool:
        return self._ch is not None

    def open(self) -> None:
        if self._ch is not None:
            return
        p = self._profile
        try:
            self._ch = self._factory(p.host, p.port, p.connect_timeout_s)
        except Failure:
            raise
        except Exception as exc:
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"TELNET_OPEN_FAILED: {type(exc).__name__}: {exc}",),
            ) from exc
        # Login exchange — typed failure if it can't complete.
        try:
            self._ch.read_until(p.login_prompt, timeout=p.connect_timeout_s)
            self._ch.write(p.username.encode("utf-8") + b"\r\n")
            if p.password:
                self._ch.read_until(p.password_prompt, timeout=p.connect_timeout_s)
                self._ch.write(p.password.encode("utf-8") + b"\r\n")
        except Exception as exc:
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"TELNET_LOGIN_FAILED: {type(exc).__name__}: {exc}",),
            ) from exc

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes:
        if self._ch is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=("SESSION_NOT_OPEN: call open() first",))
        if timeout_s is None:
            timeout_s = self._profile.read_timeout_s
        timeout_s = min(timeout_s, self._profile.max_read_s)
        try:
            self._ch.write(command.encode("utf-8") + b"\r\n")
            buf = self._ch.read_until(b"\n", timeout=timeout_s)
        except Exception as exc:
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"TELNET_COMMAND_FAILED: {type(exc).__name__}: {exc}",),
                retry_hint="re-open the telnet session",
            ) from exc
        if not buf:
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"TELNET_EMPTY_RESPONSE: command {command!r} returned nothing",),
                retry_hint="re-open the telnet session",
            )
        return buf

    def close(self) -> None:
        if self._ch is not None:
            try:
                self._ch.close()
            except Exception:  # noqa: BLE001
                pass
            self._ch = None

    def __enter__(self) -> "TelnetConsoleTransport":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ----------------- in-process mock for tests -----------------


@dataclass
class FakeTelnetChannel:
    """A fully-deterministic in-memory telnet replacement for tests."""

    responses: list[bytes] = None  # type: ignore[assignment]
    opened: bool = False
    closed: bool = False
    written: list[bytes] = None  # type: ignore[assignment]
    connect_fail: Optional[Exception] = None
    login_prompt_response: bytes = b"login: "
    password_prompt_response: bytes = b"Password: "

    def __post_init__(self) -> None:
        if self.responses is None:
            self.responses = []
        if self.written is None:
            self.written = []

    def read_until(self, match: bytes | str, timeout: float | None = None) -> bytes:
        if isinstance(match, bytes) and match == b"login:":
            return self.login_prompt_response
        if isinstance(match, bytes) and match == b"Password:":
            return self.password_prompt_response
        if self.responses:
            return self.responses.pop(0)
        return b""

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closed = True


def fake_telnet_factory(channel: FakeTelnetChannel) -> TelnetDriverFactory:
    def _factory(host: str, port: int, timeout: float) -> TelnetChannelLike:
        if channel.connect_fail is not None:
            raise channel.connect_fail
        channel.opened = True
        return channel
    return _factory
