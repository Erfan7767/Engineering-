"""A management factory must be usable *while* discovery is still running.

``netops-autopilot autopilot --mgmt-user …`` advertised an out-of-band path
to every discovered device, and it was inert. Measured: with a real
``MgmtSessionFactory`` and working credentials, every neighbour was refused
``CRAWL_NOT_BOUND: no discovery evidence available`` and only the device on
the console cable was configured.

The cause was ordering, not policy. ``AutopilotEngine`` binds the discovery
evidence to the factory only immediately before the execution gate — but the
crawl itself asks the factory to open neighbour sessions *during* discovery,
before any evidence exists to bind. The factory then refused for a reason
that described its own internal state, not the device.

Discovery is not evidence-free, though: the neighbour's LLDP/CDP
advertisement stated a vendor and a management address, and the crawl passes
both. Those are observations from the device itself. This covers the
contract — the hint is used only while nothing is bound, and ignored
entirely the moment recorded evidence exists.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netops_autopilot.access.mgmt_session import MgmtCredential, MgmtSessionFactory
from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.discovery_crawl import _open_session

_GOLDEN = (
    "src/netops_autopilot/simfabric/fixtures/golden/cisco_iosxe/show_version.txt"
)
_SERIAL = "DOG2734L0XX"          # what that golden output actually contains

_CRED = MgmtCredential(username="netops", password="s3cr3t", method="ssh")


def _golden() -> bytes:
    with open(_GOLDEN, "rb") as fh:
        return fh.read()


class _Session:
    """Answers the identity command with the real golden bytes."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def execute(self, command: str, timeout_s: float | None = None) -> bytes:
        self.executed.append(command)
        if command.strip() == "show version":
            return _golden()
        return b""

    def close(self) -> None:
        self.closed = True


class _Recorder:
    """Stands in for the transport selector and keeps the spec it was given."""

    def __init__(self) -> None:
        self.specs = []
        self.session = _Session()

    def __call__(self, spec):
        self.specs.append(spec)
        return self.session


def _factory(connect, *, allow_unverified: bool = True) -> MgmtSessionFactory:
    return MgmtSessionFactory(
        credential_provider=lambda ref, fam: _CRED,
        allow_unverified_identity=allow_unverified,
        connect=connect,
    )


# --------------------------------------------------------------------------
# The unbound path: discovery's own observations are the evidence
# --------------------------------------------------------------------------


def test_an_advertised_neighbour_is_really_dialled() -> None:
    connect = _Recorder()
    factory = _factory(connect)

    session = factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    assert session is connect.session
    spec = connect.specs[0]
    assert spec.ssh_host == "10.99.0.2"          # the address it advertised
    assert spec.ssh_port == 22
    assert spec.ssh_username == "netops"
    assert connect.session.opened is True
    # Identity was read from the device, with the family's own command.
    assert "show version" in connect.session.executed


def test_a_telnet_credential_dials_telnet() -> None:
    connect = _Recorder()
    factory = MgmtSessionFactory(
        credential_provider=lambda ref, fam: MgmtCredential(
            username="netops", password="s3cr3t", method="telnet"),
        allow_unverified_identity=True, connect=connect)

    factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    spec = connect.specs[0]
    assert spec.telnet_host == "10.99.0.2"
    assert spec.telnet_port == 23


def test_first_contact_is_unverified_and_says_so() -> None:
    """No serial has been recorded yet, so it cannot be confirmed."""
    connect = _Recorder()
    factory = _factory(connect, allow_unverified=True)

    factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    checks = factory.confirmed_identities
    assert len(checks) == 1
    assert checks[0].status == "UNVERIFIED"
    assert checks[0].expected_serial is None
    assert checks[0].observed_serial == _SERIAL      # really parsed


def test_without_the_operator_flag_first_contact_is_refused() -> None:
    """And the session it opened is closed, not leaked."""
    connect = _Recorder()
    factory = _factory(connect, allow_unverified=False)

    with pytest.raises(Failure) as exc:
        factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    assert "IDENTITY_UNVERIFIED:access-sw1" in str(exc.value)
    assert connect.session.closed is True


# --------------------------------------------------------------------------
# The safety invariant: recorded evidence always wins
# --------------------------------------------------------------------------


def _bound_crawl(address: str, serial: str | None):
    return SimpleNamespace(devices=[SimpleNamespace(
        device_ref="access-sw1",
        mgmt_addresses=(address,),
        identity=SimpleNamespace(vendor_family="cisco/ios-xe", serial=serial),
    )])


def test_a_bound_crawl_overrides_the_hint() -> None:
    """Once discovery has recorded evidence, the hint is ignored entirely."""
    connect = _Recorder()
    factory = _factory(connect, allow_unverified=True)
    factory.bind_crawl(_bound_crawl("10.0.0.9", _SERIAL))

    factory("access-sw1", ("192.0.2.250",), "juniper/junos")

    # The recorded address was dialled, not the advertised one passed in,
    # and the recorded family chose the dialect — not the hint.
    assert connect.specs[0].ssh_host == "10.0.0.9"
    assert factory.confirmed_identities[0].status == "CONFIRMED"


def test_a_bound_crawl_still_catches_a_wrong_device() -> None:
    connect = _Recorder()
    factory = _factory(connect, allow_unverified=True)
    factory.bind_crawl(_bound_crawl("10.0.0.9", "SOMEOTHERSERIAL"))

    with pytest.raises(Failure) as exc:
        factory("access-sw1", ("192.0.2.250",), "cisco/ios-xe")

    assert "IDENTITY_MISMATCH:access-sw1" in str(exc.value)


# --------------------------------------------------------------------------
# The hint travels only to factories that can take it
# --------------------------------------------------------------------------


def test_the_hint_reaches_a_factory_that_accepts_it() -> None:
    seen = []

    class _TakesHint:
        def open(self, device_ref, hints, family_hint=""):
            seen.append((device_ref, hints, family_hint))
            return _Session()

    _open_session(_TakesHint(), "dev-02", ("10.0.0.2",), "cisco/ios-xe")
    assert seen == [("dev-02", ("10.0.0.2",), "cisco/ios-xe")]


def test_a_factory_with_the_old_signature_is_still_supported() -> None:
    """Nine test doubles and the simulated fabric take only two arguments."""
    seen = []

    class _OldStyle:
        def open(self, device_ref, hints):
            seen.append((device_ref, hints))
            return _Session()

    _open_session(_OldStyle(), "dev-02", ("10.0.0.2",), "cisco/ios-xe")
    assert seen == [("dev-02", ("10.0.0.2",))]


def test_a_bare_callable_factory_is_supported() -> None:
    seen = []

    def _callable(device_ref, hints):
        seen.append(device_ref)
        return _Session()

    _open_session(_callable, "dev-02", ("10.0.0.2",), "cisco/ios-xe")
    assert seen == ["dev-02"]


def test_a_varargs_factory_receives_the_hint() -> None:
    seen = []

    class _VarArgs:
        def open(self, *args):
            seen.append(args)
            return _Session()

    _open_session(_VarArgs(), "dev-02", ("10.0.0.2",), "cisco/ios-xe")
    assert seen == [("dev-02", ("10.0.0.2",), "cisco/ios-xe")]


# --------------------------------------------------------------------------
# Asking for a secret where there is no terminal to ask on
# --------------------------------------------------------------------------


def test_no_terminal_yields_a_typed_refusal_not_a_raw_oserror() -> None:
    """Discovery now reaches this mid-crawl, often with no tty attached.

    ``getpass`` answers that with a bare ``OSError`` naming neither the
    device nor the remedy; the typed failure names both.
    """
    import getpass

    from netops_autopilot.cli_main import _make_credential_provider

    def _no_tty(prompt=""):
        raise OSError(6, "No such device or address", "/dev/tty")

    original = getpass.getpass
    getpass.getpass = _no_tty
    try:
        provider = _make_credential_provider("ssh", username=None)
        with pytest.raises(Failure) as exc:
            provider("access-sw1", "cisco/ios-xe")
    finally:
        getpass.getpass = original

    message = str(exc.value)
    assert "NO_TERMINAL_FOR_CREDENTIALS" in message
    assert "OSError" in message
    assert "--mgmt-user" in message


def test_an_empty_username_is_refused_typed() -> None:
    """The platform never falls back to a default account.

    This raise was unreachable before: ``FailureClass`` was not imported at
    module scope, so an empty username produced ``NameError`` instead of the
    refusal it was written to produce.
    """
    import getpass

    from netops_autopilot.cli_main import _make_credential_provider

    original = getpass.getpass
    getpass.getpass = lambda prompt="": ""
    try:
        provider = _make_credential_provider("ssh", username=None)
        with pytest.raises(Failure) as exc:
            provider("access-sw1", "cisco/ios-xe")
    finally:
        getpass.getpass = original

    assert "NO_CREDENTIALS" in str(exc.value)
    assert "access-sw1" in str(exc.value)


# --------------------------------------------------------------------------
# The device's own banner is checked against the advertised dialect
# --------------------------------------------------------------------------

_JUNOS_BANNER = (
    b"Juniper Networks, Inc. ex2300-48p internet router, "
    b"kernel JUNOS 15.1X53-D59.0\n"
)
_CISCO_BANNER = (
    b"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
    b"(CAT3K_CAA-UNIVERSALK9-M), Version 16.9.4, RELEASE SOFTWARE\n"
)


class _BannerSession(_Session):
    def __init__(self, banner: bytes) -> None:
        super().__init__()
        self.banner = banner


class _BannerRecorder(_Recorder):
    def __init__(self, banner: bytes) -> None:
        super().__init__()
        self.session = _BannerSession(banner)


def test_a_banner_contradicting_the_advertisement_is_a_refusal() -> None:
    """The family came from an advertisement; the device gets the last word.

    Configuring a Juniper with IOS commands is not a cosmetic mistake, so a
    contradiction stops the run rather than being logged.
    """
    connect = _BannerRecorder(_JUNOS_BANNER)
    factory = _factory(connect, allow_unverified=True)

    with pytest.raises(Failure) as exc:
        factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    assert "IDENTITY_MISMATCH:access-sw1" in str(exc.value)
    assert "junos" in str(exc.value)
    # the session it opened is not left behind
    assert connect.session.closed is True
    # and nothing was configured in the wrong dialect
    assert factory.confirmed_identities == []


def test_a_banner_agreeing_with_the_advertisement_proceeds() -> None:
    connect = _BannerRecorder(_CISCO_BANNER)
    factory = _factory(connect, allow_unverified=True)

    session = factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    assert session is connect.session
    assert len(factory.confirmed_identities) == 1


def test_a_banner_that_names_no_vendor_is_not_treated_as_a_mismatch() -> None:
    """Silence is not evidence of a contradiction."""
    connect = _BannerRecorder(b"Welcome. Authorised use only.\n")
    factory = _factory(connect, allow_unverified=True)

    session = factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe")

    assert session is connect.session
    assert len(factory.confirmed_identities) == 1


def test_a_session_with_no_banner_at_all_still_works() -> None:
    """Most test doubles and some devices send none; absence is not a fault."""
    connect = _Recorder()
    factory = _factory(connect, allow_unverified=True)

    assert factory("access-sw1", ("10.99.0.2",), "cisco/ios-xe") is connect.session


def test_recorded_identity_is_confirmed_by_serial_not_by_banner() -> None:
    """The banner check belongs to the advertised path only.

    Once discovery has recorded a serial, that is the stronger evidence and
    the existing confirmation is unchanged — a banner is not allowed to
    override a serial match.
    """
    connect = _BannerRecorder(_JUNOS_BANNER)
    factory = _factory(connect, allow_unverified=True)
    factory.bind_crawl(_bound_crawl("10.0.0.9", _SERIAL))

    session = factory("access-sw1", ("192.0.2.250",), "juniper/junos")

    assert session is connect.session
    assert factory.confirmed_identities[0].status == "CONFIRMED"
