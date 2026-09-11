"""Tests for the transport factory."""

from __future__ import annotations

import pytest

from netops_autopilot.access.transport_factory import TransportSpec, select_transport
from netops_autopilot.access.serial_transport import SerialConsoleTransport
from netops_autopilot.access.ssh_transport import SSHConsoleTransport
from netops_autopilot.access.telnet_transport import TelnetConsoleTransport
from netops_autopilot.core.failures import Failure, FailureClass


def test_serial_port_wins():
    spec = TransportSpec(serial_port="COM5", ssh_host="1.2.3.4", ssh_username="u")
    t = select_transport(spec)
    assert isinstance(t, SerialConsoleTransport)


def test_ssh_when_no_serial():
    spec = TransportSpec(ssh_host="1.2.3.4", ssh_username="u", ssh_password="p")
    t = select_transport(spec)
    assert isinstance(t, SSHConsoleTransport)


def test_telnet_when_no_serial_or_ssh():
    spec = TransportSpec(telnet_host="1.2.3.4", telnet_username="u", telnet_password="p")
    t = select_transport(spec)
    assert isinstance(t, TelnetConsoleTransport)


def test_blocks_when_nothing_specified():
    spec = TransportSpec()
    with pytest.raises(Failure) as exc:
        select_transport(spec)
    assert exc.value.cls is FailureClass.BLOCKED
    assert "NO_TRANSPORT_SPECIFIED" in exc.value.causes[0]


def test_serial_with_baud_override():
    spec = TransportSpec(serial_port="COM5", serial_baud=115200)
    t = select_transport(spec)
    assert isinstance(t, SerialConsoleTransport)
    # The baud should be the first candidate.
    assert t._profile.baud_candidates[0] == 115200


def test_ssh_defaults_port_and_device_type():
    spec = TransportSpec(ssh_host="h", ssh_username="u")
    t = select_transport(spec)
    assert isinstance(t, SSHConsoleTransport)
    assert t._profile.port == 22
    assert t._profile.device_type == "autodetect"


def test_telnet_defaults_port():
    spec = TransportSpec(telnet_host="h", telnet_username="u")
    t = select_transport(spec)
    assert isinstance(t, TelnetConsoleTransport)
    assert t._profile.port == 23


def test_ssh_host_without_username_blocks():
    """Without a username, we must NOT silently pick SSH."""
    spec = TransportSpec(ssh_host="1.2.3.4")
    with pytest.raises(Failure):
        select_transport(spec)
