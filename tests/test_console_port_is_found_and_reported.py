"""An operator can find the console port, and a bad one is explained.

``autopilot --port`` requires a device name and the only guidance was the
string "COMx / /dev/ttyUSB0". Someone who has just racked a switch and plugged
in a USB console adapter has no way to know what it enumerated as — on Linux it
is not always ttyUSB0. ``access.connection.list_serial_ports`` could already
answer that; it was never reachable from the command line.

Worse, naming a port that could not be opened did not fail — it crashed. The
``self._factory(...)`` call in ``SerialConsoleTransport.open`` sits outside the
baud probe's ``try``, so pySerial's ``SerialException`` escaped as a raw
traceback. The ``except Exception`` a few lines below, which turns probe errors
into a typed ``NO_BAUD_RESPONSE``, never saw it.
"""

from __future__ import annotations

import pytest

from netops_autopilot.access.serial_transport import _pyserial_factory
from netops_autopilot.core.failures import Failure


def test_a_port_that_cannot_be_opened_is_a_typed_failure_not_a_traceback():
    with pytest.raises(Failure) as excinfo:
        _pyserial_factory("/dev/definitely-not-a-real-port", 9600, 0.05)
    cause = excinfo.value.causes[0]
    assert cause.startswith("SERIAL_PORT_UNAVAILABLE:"), cause
    assert "/dev/definitely-not-a-real-port" in cause


def test_the_failure_lists_the_ports_that_do_exist():
    """"could not open port" without the alternatives leaves a guessing game."""
    with pytest.raises(Failure) as excinfo:
        _pyserial_factory("/dev/definitely-not-a-real-port", 9600, 0.05)
    cause = excinfo.value.causes[0]
    assert "Serial ports present:" in cause, cause
    assert "netops-autopilot ports" in cause, cause


def test_the_driver_being_absent_is_still_its_own_typed_state(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def blind(name, *a, **k):
        if name == "serial":
            raise ImportError("no module named serial")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blind)
    with pytest.raises(Failure) as excinfo:
        _pyserial_factory("/dev/ttyS0", 9600, 0.05)
    assert "SERIAL_DRIVER_UNAVAILABLE" in excinfo.value.causes[0]


def test_run_ports_lists_what_the_machine_sees(monkeypatch, capsys):
    from netops_autopilot.access.connection import DiscoveredPort
    from netops_autopilot.cli_main import run_ports

    monkeypatch.setattr(
        "netops_autopilot.access.connection.list_serial_ports",
        lambda: [DiscoveredPort(device="/dev/ttyUSB0",
                                description="FT232R USB UART",
                                hwid="USB VID:PID=0403:6001",
                                manufacturer="FTDI", product="", serial_number="")])
    assert run_ports() == 0
    out = capsys.readouterr().out
    assert "/dev/ttyUSB0" in out
    assert "FT232R USB UART" in out
    assert "autopilot --port" in out


def test_no_visible_port_is_a_failure_state_not_a_success(monkeypatch, capsys):
    """Nothing to connect to is something the operator must act on."""
    from netops_autopilot.cli_main import run_ports

    monkeypatch.setattr("netops_autopilot.access.connection.list_serial_ports",
                        lambda: [])
    assert run_ports() == 1
    out = capsys.readouterr().out
    assert "none" in out
    assert "console cable" in out


def test_the_ports_command_is_reachable_from_the_command_line():
    from netops_autopilot.cli_main import main

    # --help on the subparser proves the subcommand is registered; a missing
    # one exits 2 from argparse.
    with pytest.raises(SystemExit) as excinfo:
        main(["ports", "--help"])
    assert excinfo.value.code == 0
