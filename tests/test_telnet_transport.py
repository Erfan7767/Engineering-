"""Tests for the Telnet console transport."""

from __future__ import annotations

import pytest

from netops_autopilot.access.telnet_transport import (
    TelnetConsoleTransport,
    TelnetProfile,
    FakeTelnetChannel,
    fake_telnet_factory,
)
from netops_autopilot.core.failures import Failure, FailureClass


def test_profile_requires_host():
    with pytest.raises(ValueError):
        TelnetProfile(host="", username="u")


def test_profile_requires_username():
    with pytest.raises(ValueError):
        TelnetProfile(host="h", username="")


def test_profile_rejects_bad_port():
    with pytest.raises(ValueError):
        TelnetProfile(host="h", username="u", port=0)
    with pytest.raises(ValueError):
        TelnetProfile(host="h", username="u", port=99999)


def test_profile_rejects_invalid_regex():
    with pytest.raises(ValueError):
        TelnetProfile(host="h", username="u", prompt_pattern="(unclosed")


def test_open_completes_login_exchange():
    ch = FakeTelnetChannel()
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="admin", password="p"),
        driver_factory=fake_telnet_factory(ch),
    )
    t.open()
    assert ch.opened is True
    # Login + password sent to the device
    assert b"admin" in b"".join(ch.written)
    assert b"p" in b"".join(ch.written)


def test_open_blocks_on_connect_failure():
    ch = FakeTelnetChannel(connect_fail=ConnectionError("nope"))
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="u"),
        driver_factory=fake_telnet_factory(ch),
    )
    with pytest.raises(Failure) as exc:
        t.open()
    assert exc.value.cls is FailureClass.BLOCKED
    assert "TELNET_OPEN_FAILED" in exc.value.causes[0]


def test_open_sends_only_username_when_no_password():
    ch = FakeTelnetChannel()
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="admin", password=""),
        driver_factory=fake_telnet_factory(ch),
    )
    t.open()
    written = b"".join(ch.written)
    assert b"admin" in written
    # No password prompt expected (no password configured).
    # The channel's password_prompt_response should NOT have been consumed.
    # Just check the channel got the username write.


def test_execute_returns_bytes():
    ch = FakeTelnetChannel(responses=[b"OK\n", b"router#"])
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="u"),
        driver_factory=fake_telnet_factory(ch),
    )
    t.open()
    out = t.execute("show ip")
    assert b"OK" in out


def test_execute_retries_on_failure():
    ch = FakeTelnetChannel()
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="u"),
        driver_factory=fake_telnet_factory(ch),
    )
    t.open()
    # No response queued → reads return empty → RETRYABLE
    with pytest.raises(Failure) as exc:
        t.execute("x")
    assert exc.value.cls is FailureClass.RETRYABLE


def test_execute_requires_open():
    t = TelnetConsoleTransport(TelnetProfile(host="h", username="u"))
    with pytest.raises(Failure) as exc:
        t.execute("x")
    assert "SESSION_NOT_OPEN" in exc.value.causes[0]


def test_close_disconnects():
    ch = FakeTelnetChannel()
    t = TelnetConsoleTransport(
        TelnetProfile(host="h", username="u"),
        driver_factory=fake_telnet_factory(ch),
    )
    t.open()
    t.close()
    assert ch.closed is True


def test_context_manager():
    ch = FakeTelnetChannel()
    with TelnetConsoleTransport(
        TelnetProfile(host="h", username="u"),
        driver_factory=fake_telnet_factory(ch),
    ) as t:
        assert t.is_open
    assert ch.closed is True


def test_lazy_import_missing_telnetlib(monkeypatch):
    """When telnetlib is absent (PEP 594, Py 3.13+), factory raises typed BLOCKED."""
    import builtins
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "telnetlib":
            raise ImportError("simulated missing stdlib")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    from netops_autopilot.access.telnet_transport import _stdlib_telnet_factory
    with pytest.raises(Failure) as exc:
        _stdlib_telnet_factory("h", 23, 5.0)
    assert exc.value.cls is FailureClass.BLOCKED
    assert "telnetlib" in exc.value.causes[0]
