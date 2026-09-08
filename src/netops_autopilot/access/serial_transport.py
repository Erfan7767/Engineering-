"""Serial console transport — the first REAL ExecSession (E01/E02, §9).

Deterministic by construction:
* Clock and sleep are injected (tests run on fake time; zero wall-clock
  dependence, zero randomness).
* Baud selection is an ordered probe over ``baud_candidates`` — the first
  candidate that yields decodable activity wins; silence/garbage advances
  the probe (hypothesis testing, not guessing, L01).
* Framing = quiet-period OR prompt match, under a hard read cap; timeout ⇒
  ``TimeoutError`` (the Collector maps it to RETRYABLE, breaker counts it).

The pySerial dependency is resolved lazily at factory call so the module
imports (and is testable) without the driver installed; a missing driver is
a typed BLOCKED failure (T2), never an ImportError crash.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from ..core.failures import Failure, FailureClass


class SerialPortLike(Protocol):
    """The pySerial surface this transport uses (kept minimal)."""

    def write(self, data: bytes) -> int: ...
    def read(self, size: int = 1) -> bytes: ...
    def reset_input_buffer(self) -> None: ...
    def close(self) -> None: ...


PortFactory = Callable[[str, int, float], SerialPortLike]
Clock = Callable[[], float]
Sleep = Callable[[float], None]


@dataclass(frozen=True)
class SerialProfile:
    """Console profile — populated from Default Access Profiles (§9),
    never hardcoded per vendor name."""

    port: str
    baud_candidates: tuple[int, ...] = (9600, 115200)
    read_slice_timeout_s: float = 0.05
    baud_probe_window_s: float = 0.8
    quiet_period_s: float = 0.35
    max_read_s: float = 30.0
    prompt_pattern: str = r"(?:^|[\r\n])[^\r\n]*[>#]\s*$"

    def __post_init__(self) -> None:
        if not self.baud_candidates:
            raise ValueError("baud_candidates must not be empty")
        if self.quiet_period_s <= 0 or self.max_read_s <= 0:
            raise ValueError("quiet_period_s and max_read_s must be positive")
        try:
            re.compile(self.prompt_pattern)
        except re.error as exc:
            raise ValueError(f"prompt_pattern does not compile: {exc}") from exc


def _decodable(data: bytes) -> bool:
    """Console activity check: printable ASCII + CR/LF/TAB only."""
    return len(data) > 0 and all(b in (9, 10, 13) or 32 <= b <= 126 for b in data)


def _pyserial_factory(port: str, baud: int, read_timeout_s: float) -> SerialPortLike:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=("SERIAL_DRIVER_UNAVAILABLE: pySerial not installed (ADR-0008 bundles it in the MSI)",),
        ) from exc
    return serial.Serial(port=port, baudrate=baud, timeout=read_timeout_s)


class SerialConsoleTransport:
    """ExecSession over a physical console port."""

    def __init__(
        self,
        profile: SerialProfile,
        port_factory: Optional[PortFactory] = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._profile = profile
        self._factory = port_factory or _pyserial_factory
        self._clock = clock
        self._sleep = sleep
        self._port: Optional[SerialPortLike] = None
        self._baud: Optional[int] = None
        self._prompt = re.compile(profile.prompt_pattern)

    @property
    def negotiated_baud(self) -> Optional[int]:
        return self._baud

    # ------------------------------------------------------------------ open
    def open(self) -> None:
        """Probe baud candidates in order; bind the first that answers with
        decodable bytes. All-silent ⇒ BLOCKED (no device assumption)."""
        profile = self._profile
        probe_errors: list[str] = []
        for baud in profile.baud_candidates:
            port = self._factory(profile.port, baud, profile.read_slice_timeout_s)
            try:
                port.reset_input_buffer()
                port.write(b"\r")
                deadline = self._clock() + profile.baud_probe_window_s
                buf = bytearray()
                while self._clock() < deadline:
                    chunk = port.read(4096)
                    if chunk:
                        buf.extend(chunk)
                    else:
                        self._sleep(profile.read_slice_timeout_s)
                if buf and _decodable(bytes(buf)):
                    self._port = port
                    self._baud = baud
                    return
            except Failure:
                raise
            except Exception as exc:  # transport-level probe error ⇒ next candidate
                probe_errors.append(f"{baud}:{type(exc).__name__}")
            finally:
                if self._port is not port:
                    port.close()
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=(
                f"NO_BAUD_RESPONSE: port={profile.port} candidates={list(profile.baud_candidates)}",
                *(f"PROBE_ERROR {e}" for e in probe_errors),
            ),
        )

    # --------------------------------------------------------------- execute
    def execute(self, command: str, timeout_s: float) -> bytes:
        if self._port is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=("SESSION_NOT_OPEN: call open() first",))
        port = self._port
        profile = self._profile
        deadline = self._clock() + min(timeout_s, profile.max_read_s)

        port.reset_input_buffer()
        port.write(command.encode("utf-8") + b"\r")

        buf = bytearray()
        last_data_at = self._clock()
        while True:
            now = self._clock()
            if now >= deadline:
                raise TimeoutError(f"serial read exceeded {min(timeout_s, profile.max_read_s)}s for {command!r}")
            chunk = port.read(4096)
            if chunk:
                buf.extend(chunk)
                last_data_at = self._clock()
                if self._prompt.search(bytes(buf).decode("utf-8", errors="replace")):
                    break
            else:
                if buf and (self._clock() - last_data_at) >= profile.quiet_period_s:
                    break
                self._sleep(profile.read_slice_timeout_s)
        return bytes(buf)

    # ----------------------------------------------------------------- close
    def close(self) -> None:
        if self._port is not None:
            self._port.close()
            self._port = None
            self._baud = None
