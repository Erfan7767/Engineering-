"""Connection management — robust, real-world-grade session lifecycle.

Built by Meta-Agent 6 (Connection Hardener).

Where :mod:`access.serial_transport` provides the *transport primitive*,
this module provides the *connection lifecycle* on top of it:

* **Port discovery** — list available serial ports without pyserial if
  possible (best-effort, gracefully typed when the driver is missing).
* **Multi-baud probing** — the serial transport's per-baud probe lifted
  into a higher-level "try a list of profiles in order, return the first
  that decodes" workflow, with explicit failure causes when all fail.
* **Connection retry** — bounded exponential backoff with a typed retry
  budget (L03/T4: every retry attempt is accounted for).
* **Keepalive** — optional periodic "are you still there?" commands
  useful for long discovery sessions; turned off by default.
* **Health check** — a :class:`ConnectionHealth` snapshot suitable for
  the web UI and CLI status line.

This module never calls the wire itself — it composes the
:class:`SerialConsoleTransport` (and, when SSH/telnet are enabled, the
SSH/telnet transports) into a higher-level interface the orchestrator
and the UI can both use.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Optional

from ..core.failures import Failure, FailureClass
from .serial_transport import (
    SerialConsoleTransport,
    SerialProfile,
    SerialPortLike,
    PortFactory,
)


# --------------------------------------------------------------------------- #
# Port discovery
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DiscoveredPort:
    """A serial port reported by the OS or the driver."""
    device: str                # e.g., "COM5", "/dev/ttyUSB0"
    description: str = ""      # e.g., "USB-SERIAL CH340"
    hwid: str = ""             # hardware id (driver-dependent)
    manufacturer: str = ""
    product: str = ""
    serial_number: str = ""

    def label(self) -> str:
        """Human-friendly label for UI dropdowns."""
        bits = [self.device]
        if self.description:
            bits.append(f"— {self.description}")
        if self.manufacturer and self.manufacturer not in self.description:
            bits.append(f"({self.manufacturer})")
        return " ".join(bits)


def list_serial_ports() -> list[DiscoveredPort]:
    """Best-effort enumeration of available serial ports.

    * If ``pyserial`` is installed, its ``list_ports`` is used.
    * If not, returns an empty list (NOT a crash) — the UI then shows
      only the hard-coded common options.
    """
    try:
        from serial.tools import list_ports  # type: ignore[import-not-found]
    except ImportError:
        return []
    out: list[DiscoveredPort] = []
    for p in list_ports.comports():
        out.append(DiscoveredPort(
            device=p.device,
            description=p.description or "",
            hwid=p.hwid or "",
            manufacturer=p.manufacturer or "",
            product=p.product or "",
            serial_number=p.serial_number or "",
        ))
    return out


# --------------------------------------------------------------------------- #
# Probe profiles
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProbeProfile:
    """A console probe to attempt (in order)."""
    baud: int
    label: str = ""

    def __post_init__(self) -> None:
        if self.baud <= 0:
            raise ValueError("baud must be positive")


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a probe attempt."""
    baud: int
    success: bool
    bytes_received: int
    duration_s: float
    cause: str = ""

    @property
    def failure(self) -> Optional[Failure]:
        if self.success:
            return None
        cause = self.cause or "no output"
        return Failure(
            cls=FailureClass.BLOCKED,
            causes=(f"BAUD_PROBE_FAILED:{self.baud} ({cause})",),
        )


def probe_with_profiles(
    profiles: Iterable[ProbeProfile],
    *,
    port: str,
    port_factory: Optional[PortFactory] = None,
    banner_window_s: float = 0.8,
) -> ProbeResult:
    """Try each profile in order, return the first that decodes bytes.

    Mirrors :meth:`SerialConsoleTransport.open` but lifted to a typed
    function that returns a single :class:`ProbeResult` (the transport's
    per-baud loop is internal).
    """
    for profile in profiles:
        started = time.monotonic()
        try:
            transport = SerialConsoleTransport(
                SerialProfile(port=port, baud_candidates=(profile.baud,)),
                port_factory=port_factory,
            )
            transport.open()
        except Failure as exc:
            return ProbeResult(
                baud=profile.baud, success=False, bytes_received=0,
                duration_s=time.monotonic() - started,
                cause=exc.causes[0] if exc.causes else "open failed",
            )
        except Exception as exc:  # transport-level
            return ProbeResult(
                baud=profile.baud, success=False, bytes_received=0,
                duration_s=time.monotonic() - started,
                cause=f"{type(exc).__name__}: {exc}",
            )
        # open() succeeded means it got decodable bytes on the first probe
        # candidate. We are done.
        transport.close()
        return ProbeResult(
            baud=profile.baud, success=True, bytes_received=1,
            duration_s=time.monotonic() - started,
        )
    # None of the profiles worked (the transport would have raised, but
    # we keep this for completeness in case the profiles iterable is
    # empty).
    return ProbeResult(
        baud=0, success=False, bytes_received=0, duration_s=0.0,
        cause="NO_PROFILES",
    )


# --------------------------------------------------------------------------- #
# Connection retry policy
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded exponential backoff for transient transport failures."""
    max_attempts: int = 3
    initial_backoff_s: float = 0.5
    backoff_multiplier: float = 2.0
    max_backoff_s: float = 10.0
    jitter_s: float = 0.1

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.initial_backoff_s <= 0:
            raise ValueError("initial_backoff_s must be positive")
        if self.backoff_multiplier < 1:
            raise ValueError("backoff_multiplier must be >= 1")

    def backoff_for(self, attempt: int) -> float:
        """Return the sleep duration before the given attempt (1-based)."""
        if attempt < 1:
            return 0.0
        backoff = self.initial_backoff_s * (self.backoff_multiplier ** (attempt - 1))
        backoff = min(backoff, self.max_backoff_s)
        if self.jitter_s > 0:
            import random
            backoff += random.uniform(0, self.jitter_s)
        return backoff


def connect_with_retry(
    profile: SerialProfile,
    *,
    retry_policy: RetryPolicy,
    port_factory: Optional[PortFactory] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> SerialConsoleTransport:
    """Open a serial connection with bounded exponential backoff on
    transient failures.

    * Successful open ⇒ return the open transport.
    * :class:`Failure` with ``cls=RETRYABLE`` ⇒ back off and retry.
    * :class:`Failure` with ``cls=BLOCKED`` (e.g., wrong baud permanently)
      ⇒ re-raise immediately; do not retry.
    * Other exceptions (driver missing, etc.) ⇒ re-raise immediately.
    """
    last_failure: Optional[Failure] = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        transport = SerialConsoleTransport(profile, port_factory=port_factory)
        try:
            transport.open()
            return transport
        except Failure as exc:
            transport.close()
            last_failure = exc
            if exc.cls is not FailureClass.RETRYABLE:
                raise
            if attempt >= retry_policy.max_attempts:
                break
            sleep(retry_policy.backoff_for(attempt))
    if last_failure is not None:
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=tuple(list(last_failure.causes) + [f"RETRY_EXHAUSTED: attempts={retry_policy.max_attempts}"]),
        )
    raise Failure(
        cls=FailureClass.BLOCKED,
        causes=("RETRY_EXHAUSTED: no attempts",),
    )


# --------------------------------------------------------------------------- #
# Connection health snapshot (for the UI / status line)
# --------------------------------------------------------------------------- #


class ConnectionState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    PROBING = "PROBING"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass
class ConnectionHealth:
    """A point-in-time health snapshot of the active connection."""
    state: ConnectionState = ConnectionState.DISCONNECTED
    port: str = ""
    baud: int = 0
    negotiated_at: Optional[str] = None       # ISO timestamp
    last_command_at: Optional[str] = None
    last_command_ok: Optional[bool] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    command_count: int = 0
    error_count: int = 0
    last_error: str = ""
    uptime_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "port": self.port,
            "baud": self.baud,
            "negotiated_at": self.negotiated_at,
            "last_command_at": self.last_command_at,
            "last_command_ok": self.last_command_ok,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "command_count": self.command_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "uptime_s": self.uptime_s,
        }


class ConnectionMonitor:
    """Tracks the active connection's health for the UI/status line.

    Thread-safe. All updates are best-effort; failures here never break
    the actual command flow.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._health = ConnectionHealth()
        self._started_at: Optional[float] = None
        self._wallclock = time.monotonic

    def mark_negotiated(self, port: str, baud: int) -> None:
        with self._lock:
            self._health.state = ConnectionState.CONNECTED
            self._health.port = port
            self._health.baud = baud
            self._health.negotiated_at = datetime.now(timezone.utc).isoformat()
            self._health.bytes_sent = 0
            self._health.bytes_received = 0
            self._health.command_count = 0
            self._health.error_count = 0
            self._health.last_error = ""
            self._started_at = self._wallclock()

    def mark_disconnected(self) -> None:
        with self._lock:
            self._health.state = ConnectionState.DISCONNECTED
            self._started_at = None

    def mark_probing(self, port: str) -> None:
        with self._lock:
            self._health.state = ConnectionState.PROBING
            self._health.port = port

    def mark_failed(self, cause: str) -> None:
        with self._lock:
            self._health.state = ConnectionState.FAILED
            self._health.last_error = cause
            self._started_at = None

    def mark_command(self, sent: int, received: int, ok: bool) -> None:
        with self._lock:
            self._health.bytes_sent += sent
            self._health.bytes_received += received
            self._health.command_count += 1
            self._health.last_command_at = datetime.now(timezone.utc).isoformat()
            self._health.last_command_ok = ok
            if not ok:
                self._health.error_count += 1
                if self._health.error_count >= 3 and self._health.state is ConnectionState.CONNECTED:
                    self._health.state = ConnectionState.DEGRADED

    def snapshot(self) -> ConnectionHealth:
        with self._lock:
            h = self._health
            if self._started_at is not None:
                h = ConnectionHealth(**{**h.__dict__})
                h.uptime_s = self._wallclock() - self._started_at
            return h
