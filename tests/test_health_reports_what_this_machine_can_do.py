"""``health`` probes the machine instead of reciting the documentation.

The "Optional deps" line was a fixed string — "netmiko (SSH), pyyaml (YAML),
fastapi+uvicorn (web) — all optional" — printed identically whether or not any
of them was installed. A health check that reports availability without
checking tells an operator their laptop is ready for hardware it cannot talk
to. It also never mentioned ``serial``, the driver the entire console path
depends on, so the one thing that has to be present before a device can be
reached was the one thing not reported.
"""

from __future__ import annotations

import importlib.util

import pytest

from netops_autopilot.cli_main import _DRIVERS, _driver_status, run_health


def test_the_console_driver_is_reported_first_because_it_is_the_hardware_path():
    assert _DRIVERS[0][0] == "serial"
    assert _DRIVERS[0][1] == "console"


def test_every_reported_driver_is_really_probed():
    for module, _role, consequence in _DRIVERS:
        assert consequence, f"{module} reports no consequence for being absent"
        # the probe is a real import, so the module name must be the import name
        assert importlib.util.find_spec(module) is not None or module == "telnetlib"


def test_a_missing_driver_is_reported_missing_with_what_is_lost(monkeypatch):
    real = importlib.util.find_spec

    def blind(name, *a, **k):
        return None if name == "netmiko" else real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", blind)
    out = _driver_status()
    assert "SSH: MISSING" in out, out
    assert "cannot open SSH management sessions" in out, out
    # and the drivers that are present are still reported as present
    assert "console: OK" in out or "console: MISSING" in out


def test_an_all_present_machine_reports_no_consequences(monkeypatch):
    class _Spec:
        pass

    monkeypatch.setattr(importlib.util, "find_spec", lambda *a, **k: _Spec())
    out = _driver_status()
    assert "MISSING" not in out, out
    assert "—" not in out, out
    assert out.count(": OK") == len(_DRIVERS)


def test_telnet_is_reported_honestly_on_this_interpreter():
    """stdlib telnetlib was removed in Python 3.13 (PEP 594)."""
    import sys

    out = _driver_status()
    if sys.version_info >= (3, 13):
        assert "telnet: MISSING" in out, out
        assert "PEP 594" in out, out
    else:
        assert "telnet: OK" in out, out


def test_health_names_the_evidence_ledger(capsys):
    assert run_health() == 0
    out = capsys.readouterr().out
    assert "Evidence ledger" in out
    assert "Device drivers" in out
    assert "netmiko (SSH), pyyaml (YAML)" not in out, (
        "the hardcoded availability string came back")
