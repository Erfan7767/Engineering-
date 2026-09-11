"""Transport factory — select the right ExecSession for a given target.

Selection rules (L01: never assume what we haven't proven):

1. If the target has a local serial port spec → SerialConsoleTransport
   (the v1 hardware path per ADR-0004).
2. Else if SSH credentials are present → SSHConsoleTransport (modeled;
   v1 still requires the console path to be primary).
3. Else if telnet credentials are present → TelnetConsoleTransport
   (legacy; modeled; same caveat as SSH).
4. Else → typed ``Failure(BLOCKED)`` explaining which inputs are missing.

The factory returns the *unopened* transport; the caller is responsible for
calling ``.open()`` (and ``.close()``) and the Collector takes over the
framing + evidence chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from ..core.failures import Failure, FailureClass
from .serial_transport import SerialProfile, SerialConsoleTransport
from .ssh_transport import SSHProfile, SSHConsoleTransport
from .telnet_transport import TelnetProfile, TelnetConsoleTransport


class ExecSession(Protocol):
    """The minimal surface every transport exposes."""

    def open(self) -> None: ...
    def execute(self, command: str, timeout_s: float) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class TransportSpec:
    """All the inputs we *might* have for a target device.

    The factory picks the most appropriate transport; missing fields are
    an explicit outcome (BLOCKED), never a guess.
    """

    serial_port: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_device_type: Optional[str] = None
    telnet_host: Optional[str] = None
    telnet_port: Optional[int] = None
    telnet_username: Optional[str] = None
    telnet_password: Optional[str] = None
    serial_baud: int = 9600
    enable_secret: str = ""


def select_transport(spec: TransportSpec) -> ExecSession:
    """Return the highest-priority unopened transport for the spec.

    Priority: serial > ssh > telnet (matches the §9 ordering).
    """
    if spec.serial_port:
        return SerialConsoleTransport(
            SerialProfile(port=spec.serial_port, baud_candidates=(spec.serial_baud, 115200))
        )
    if spec.ssh_host and spec.ssh_username:
        return SSHConsoleTransport(
            SSHProfile(
                host=spec.ssh_host,
                port=spec.ssh_port or 22,
                username=spec.ssh_username,
                password=spec.ssh_password or "",
                device_type=spec.ssh_device_type or "autodetect",
                secret=spec.enable_secret,
            )
        )
    if spec.telnet_host and spec.telnet_username:
        return TelnetConsoleTransport(
            TelnetProfile(
                host=spec.telnet_host,
                port=spec.telnet_port or 23,
                username=spec.telnet_username,
                password=spec.telnet_password or "",
                enable_secret=spec.enable_secret,
            )
        )
    raise Failure(
        cls=FailureClass.BLOCKED,
        causes=("NO_TRANSPORT_SPECIFIED: provide either serial_port, ssh_host+username, or telnet_host+username",),
    )
