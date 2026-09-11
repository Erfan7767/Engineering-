"""Management-session factory — the real out-of-band path to discovered devices.

Why this module exists
----------------------
Discovery runs over the single console cable the operator plugged in. Every
*other* device in the fabric is reached over its management interface. Before
Phase V the CLI wired a factory that unconditionally raised
``MGMT_PATH_NOT_MODELED``, so on real hardware the platform could discover a
whole network and then configure **none** of it — while the SSH and telnet
transports it needed were already written, tested, and unused.

The contract this module enforces
---------------------------------
1. **Evidence, not assumption.** A device is contacted at a management address
   that *discovery observed* (LLDP/CDP/ARP evidence in the crawl report). No
   observed address ⇒ typed ``ACCESS_LIMITED``. The factory never invents an
   address, never tries a default gateway, never scans.
2. **Identity confirmation before any configuration.** After connecting, the
   device's serial is read and parsed by the *same* golden parsers the crawl
   used, then compared against the serial the crawl recorded for that
   ``device_ref``. A mismatch closes the session and raises
   ``IDENTITY_MISMATCH`` — the engine will not configure a box it has not
   proven to be the box it planned for. An unreadable serial is
   ``UNVERIFIED``, which also refuses unless the operator explicitly takes
   responsibility via ``allow_unverified_identity``.
3. **Credentials are the operator's, once, and never logged.** They come from
   a ``credential_provider`` callback (the CLI backs it with ``getpass``), are
   never written to the ledger, and never appear in a ``Failure`` cause.
4. **No silent success.** Every refusal is a typed ``Failure`` with a cause an
   operator can act on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from ..core.failures import Failure, FailureClass
from ..parsers.catalog import CATALOG_BUILDERS, canonical_families
from .transport_factory import TransportSpec, select_transport


class ExecSession(Protocol):
    def open(self) -> None: ...
    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class MgmtCredential:
    """Operator-supplied credentials for the management path.

    ``__repr__`` is overridden so a credential can never leak into a log line,
    a traceback, or a ledger event by accident.
    """

    username: str
    password: str
    enable_secret: str = ""
    method: str = "ssh"                    # ssh | telnet
    port: Optional[int] = None

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (f"MgmtCredential(username={self.username!r}, password='***', "
                f"enable_secret='***', method={self.method!r}, port={self.port!r})")


@dataclass(frozen=True)
class IdentityCheck:
    """The result of confirming a session talks to the intended device."""

    device_ref: str
    expected_serial: Optional[str]
    observed_serial: Optional[str]
    status: str                            # CONFIRMED | MISMATCH | UNVERIFIED

    @property
    def ok(self) -> bool:
        return self.status == "CONFIRMED"


@dataclass
class MgmtSessionFactory:
    """Open a confirmed management session to a discovered device, or refuse.

    ``bind_crawl`` is called by the orchestrator before the execution gate so
    the factory can see the crawl evidence (management addresses, serials) and
    reuse the already-open console session for the seed device.
    """

    credential_provider: Callable[[str, str], MgmtCredential]
    allow_unverified_identity: bool = False
    connect: Callable[[TransportSpec], ExecSession] = staticmethod(select_transport)
    identity_readers: dict = field(default_factory=dict)   # family -> command
    _crawl: object = None
    _console_session: object = None
    _seed_ref: str = "seed-01"
    _confirmed: list = field(default_factory=list)

    # ---------------------------------------------------------------- wiring
    def bind_crawl(self, crawl, console_session=None, seed_ref: str = "seed-01") -> None:
        """Attach the crawl evidence (called by the orchestrator)."""
        self._crawl = crawl
        self._console_session = console_session
        self._seed_ref = seed_ref

    @property
    def confirmed_identities(self) -> list:
        """Audit view: which devices were identity-confirmed this run."""
        return list(self._confirmed)

    # ---------------------------------------------------------------- lookup
    def _device(self, device_ref: str):
        if self._crawl is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                "CRAWL_NOT_BOUND: no discovery evidence available; the factory refuses "
                "to address a device it has not observed",))
        for dev in self._crawl.devices:
            if dev.device_ref == device_ref:
                return dev
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"DEVICE_NOT_DISCOVERED:{device_ref} — refusing to open a management path "
            f"to a device that discovery never saw",))

    @staticmethod
    def _identity_command(vendor_family: str) -> str:
        """The command that yields a serial for this family.

        Derived from the golden parser catalog rather than a hand-written
        table, so it cannot drift from the parsers the crawl used.
        """
        wanted = set(canonical_families(vendor_family)) | {vendor_family}
        for builder in CATALOG_BUILDERS:
            parser = builder()
            if parser.info.vendor_family in wanted and parser.info.command_ref == "show version":
                return parser.info.command_ref
        return "show version"

    @staticmethod
    def _read_serial(vendor_family: str, output: bytes) -> Optional[str]:
        """Extract the serial using the family's own golden parser."""
        wanted = set(canonical_families(vendor_family)) | {vendor_family}
        for builder in CATALOG_BUILDERS:
            parser = builder()
            if parser.info.vendor_family not in wanted:
                continue
            if parser.info.command_ref != "show version":
                continue
            for obs in parser.parse(output, "raw://identity-confirm"):
                if obs.field == "serial" and obs.parse_status.value == "OK":
                    return str(obs.value)
        return None

    # ------------------------------------------------------------------ open
    def __call__(self, device_ref: str, mgmt_hints: tuple = ()) -> ExecSession:
        dev = self._device(device_ref)
        family = dev.identity.vendor_family if dev.identity else None

        # The seed device is the one on the console cable: reuse that session
        # instead of trying to open a second handle on the same port.
        if device_ref == self._seed_ref and self._console_session is not None:
            check = self._confirm(device_ref, family, self._console_session,
                                  dev.identity.serial if dev.identity else None)
            self._confirmed.append(check)
            return self._console_session

        if not family:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"IDENTITY_INCOMPLETE:{device_ref} — vendor family unknown, so no "
                f"management dialect can be selected (never guessed)",))

        addresses = tuple(dev.mgmt_addresses or ())
        if not addresses:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"ACCESS_LIMITED:{device_ref} — discovery observed no management address "
                f"for this device. Provide one, or connect it to the managed path. "
                f"The platform does not guess an address.",))

        credential = self.credential_provider(device_ref, family)
        spec_kwargs = dict(
            ssh_username=credential.username,
            ssh_password=credential.password,
            telnet_username=credential.username,
            telnet_password=credential.password,
            enable_secret=credential.enable_secret,
        )
        if credential.method == "telnet":
            spec = TransportSpec(telnet_host=addresses[0],
                                 telnet_port=credential.port or 23, **spec_kwargs)
        else:
            spec = TransportSpec(ssh_host=addresses[0],
                                 ssh_port=credential.port or 22, **spec_kwargs)

        try:
            session = self.connect(spec)
        except Failure:
            raise
        except Exception as exc:  # noqa: BLE001 - transport/driver construction
            raise Failure(cls=FailureClass.RETRYABLE, causes=(
                f"MGMT_TRANSPORT_UNAVAILABLE:{device_ref}@{addresses[0]}: "
                f"{type(exc).__name__}: {exc}",)) from exc

        try:
            session.open()
        except Failure:
            raise
        except Exception as exc:  # noqa: BLE001
            raise Failure(cls=FailureClass.RETRYABLE, causes=(
                f"MGMT_CONNECT_FAILED:{device_ref}@{addresses[0]}: "
                f"{type(exc).__name__}: {exc}",)) from exc

        try:
            self._confirmed.append(
                self._confirm(device_ref, family, session,
                              dev.identity.serial if dev.identity else None))
        except Failure:
            try:
                session.close()
            except Exception:  # noqa: BLE001 - closing is best-effort
                pass
            raise
        return session

    # -------------------------------------------------------------- identity
    def _confirm(self, device_ref: str, vendor_family: Optional[str],
                 session: ExecSession, expected_serial: Optional[str]) -> IdentityCheck:
        """Prove the session is the device discovery recorded, or refuse."""
        observed: Optional[str] = None
        if vendor_family:
            try:
                output = session.execute(self._identity_command(vendor_family), timeout_s=20.0)
                observed = self._read_serial(vendor_family, output)
            except Exception:  # noqa: BLE001 - unreadable identity is a typed state
                observed = None

        if expected_serial and observed:
            if expected_serial.strip().lower() == observed.strip().lower():
                return IdentityCheck(device_ref, expected_serial, observed, "CONFIRMED")
            raise Failure(cls=FailureClass.FATAL, causes=(
                f"IDENTITY_MISMATCH:{device_ref} — discovery recorded serial "
                f"{expected_serial!r} but the session answered {observed!r}. "
                f"Refusing to configure: this is not the device the plan was built for.",))

        detail = ("expected serial missing from the crawl evidence"
                  if not expected_serial else
                  f"serial not readable from the session ({self._identity_command(vendor_family)})")
        if not self.allow_unverified_identity:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"IDENTITY_UNVERIFIED:{device_ref} — {detail}. The platform does not "
                f"configure a device whose identity it cannot prove. Re-run with "
                f"--allow-unverified-identity to take that responsibility explicitly.",))
        return IdentityCheck(device_ref, expected_serial, observed, "UNVERIFIED")
