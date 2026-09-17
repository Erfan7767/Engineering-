"""The management transport must be able to say who it is talking to.

A neighbour discovered from a Juniper, Aruba or FortiGate seed advertises no
vendor string — those neighbour tables have no system-description column —
and the management session protocol exposed nothing to identify it with.
The console cable gives the seed a banner; over SSH the equivalent evidence
exists, it was simply never read.

Netmiko does not surface it, but the Paramiko transport underneath does.
These tests run against a **real SSH server on a real socket**, so the bytes
asserted on are the bytes a device would send, not a canned stand-in.
"""

from __future__ import annotations

import socket
import threading

import paramiko
import pytest

from netops_autopilot.access.ssh_transport import SSHConsoleTransport, SSHProfile

pytestmark = pytest.mark.skipif(
    not hasattr(paramiko, "ServerInterface"), reason="paramiko has no server support")

_CISCO_BANNER = (
    b"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
    b"(CAT3K_CAA-UNIVERSALK9-M), Version 16.9.4, RELEASE SOFTWARE\n"
)
_JUNOS_BANNER = (
    b"Juniper Networks, Inc. ex2300-48p internet router, "
    b"kernel JUNOS 15.1X53-D59.0\n"
)


class _Server(paramiko.ServerInterface):
    """Accepts one password and sends the banner a device would send."""

    def __init__(self, banner: bytes) -> None:
        self._banner = banner

    def get_banner(self):
        return (self._banner, "en")

    def check_auth_password(self, username, password):
        return (paramiko.AUTH_SUCCESSFUL if password == "s3cr3t"
                else paramiko.AUTH_FAILED)

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True


@pytest.fixture
def ssh_server():
    """A real SSH server on a real port, sending a caller-chosen banner."""
    host_key = paramiko.RSAKey.generate(2048)
    state: dict = {"banner": _CISCO_BANNER}

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                listener.settimeout(0.3)
                conn, _addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=_Server(state["banner"]))
                channel = transport.accept(5)
                if channel is not None:
                    channel.close()
            except Exception:  # noqa: BLE001 - a peer that hangs up mid-handshake
                pass
            finally:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield state, listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=3)


def _real_session(port: int):
    """A genuinely authenticated Paramiko client to the server above."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="netops",
                   password="s3cr3t", timeout=15,
                   allow_agent=False, look_for_keys=False)
    return client


class _NetmikoShaped:
    """The three methods the transport uses, over a real Paramiko client.

    Netmiko's own connection object has exactly this shape; the only thing
    standing in for it is the wrapper, while the client, the socket and the
    banner are real.
    """

    def __init__(self, client) -> None:
        self.remote_conn = client

    def find_prompt(self, delay_factor: float = 1.0) -> str:
        return "switch# "

    def send_command(self, command: str, read_timeout: float = 30.0) -> str:
        return ""

    def disconnect(self) -> None:
        try:
            self.remote_conn.close()
        except Exception:  # noqa: BLE001
            pass


def _transport(port: int, client) -> SSHConsoleTransport:
    return SSHConsoleTransport(
        SSHProfile(host="127.0.0.1", port=port, username="netops",
                   password="s3cr3t", device_type="cisco_ios"),
        driver_factory=lambda *a, **k: _NetmikoShaped(client),
    )


def test_the_banner_a_device_sends_is_readable_from_the_session(ssh_server):
    state, port = ssh_server
    client = _real_session(port)
    try:
        transport = _transport(port, client)
        transport.open()
        assert transport.banner == _CISCO_BANNER
    finally:
        client.close()


def test_a_different_device_identifies_itself_differently(ssh_server):
    """The bytes come from the peer, not from anything the platform assumes."""
    state, port = ssh_server
    state["banner"] = _JUNOS_BANNER
    client = _real_session(port)
    try:
        transport = _transport(port, client)
        transport.open()
        assert transport.banner == _JUNOS_BANNER
        assert b"JUNOS" in transport.banner
    finally:
        client.close()


def test_the_banner_is_read_as_identity_evidence_not_decoration():
    """The platform's own family detector understands what the device said."""
    from netops_autopilot.access.vendor_detect import detect_family_candidates

    assert "cisco/ios-xe" in detect_family_candidates(_CISCO_BANNER)
    assert "junos" in detect_family_candidates(_JUNOS_BANNER)


def test_no_session_yet_means_no_banner_not_an_error():
    transport = SSHConsoleTransport(
        SSHProfile(host="127.0.0.1", port=1, username="u", password="p",
                   device_type="cisco_ios"))
    assert transport.banner == b""


def test_a_driver_that_exposes_no_banner_reports_empty_not_a_guess():
    class _NoRemoteConn:
        def find_prompt(self, delay_factor: float = 1.0) -> str:
            return "r# "

        def send_command(self, command: str, read_timeout: float = 30.0) -> str:
            return ""

        def disconnect(self) -> None:
            pass

    transport = SSHConsoleTransport(
        SSHProfile(host="127.0.0.1", port=1, username="u", password="p",
                   device_type="cisco_ios"),
        driver_factory=lambda *a, **k: _NoRemoteConn())
    transport.open()
    assert transport.banner == b""


def test_a_device_that_sends_no_banner_reports_empty(ssh_server):
    state, port = ssh_server
    state["banner"] = b""
    client = _real_session(port)
    try:
        transport = _transport(port, client)
        transport.open()
        assert transport.banner == b""
    finally:
        client.close()
