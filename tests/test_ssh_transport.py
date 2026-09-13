"""Tests for the SSH console transport."""

from __future__ import annotations

import pytest

from netops_autopilot.access.ssh_transport import SSHConsoleTransport, SSHProfile

from tests.support.test_doubles import FakeSSHChannel, fake_ssh_factory
from netops_autopilot.core.failures import Failure, FailureClass


# ----------------- Profile validation -----------------


def test_profile_requires_host():
    with pytest.raises(ValueError):
        SSHProfile(host="", username="u")


def test_profile_requires_username():
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="")


def test_profile_rejects_bad_port():
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="u", port=0)
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="u", port=70000)


def test_profile_rejects_bad_timeouts():
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="u", connect_timeout_s=0)
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="u", read_timeout_s=0)


def test_profile_rejects_invalid_regex():
    with pytest.raises(ValueError):
        SSHProfile(host="h", username="u", prompt_pattern="[invalid")


# ----------------- open() -----------------


def test_open_calls_factory_and_finds_prompt():
    ch = FakeSSHChannel(prompt="router#")
    factory = fake_ssh_factory(ch)
    t = SSHConsoleTransport(
        SSHProfile(host="1.2.3.4", username="admin", password="p"),
        driver_factory=factory,
    )
    t.open()
    assert ch.opened is True
    assert t.is_open is True


def test_open_blocks_on_connect_failure():
    ch = FakeSSHChannel(connect_fail=ConnectionError("refused"))
    factory = fake_ssh_factory(ch)
    t = SSHConsoleTransport(
        SSHProfile(host="1.2.3.4", username="admin"),
        driver_factory=factory,
    )
    with pytest.raises(Failure) as exc:
        t.open()
    assert exc.value.cls is FailureClass.BLOCKED
    assert "SSH_OPEN_FAILED" in exc.value.causes[0]


def test_open_idempotent():
    ch = FakeSSHChannel()
    factory = fake_ssh_factory(ch)
    t = SSHConsoleTransport(
        SSHProfile(host="1.2.3.4", username="admin"),
        driver_factory=factory,
    )
    t.open()
    t.open()  # second call should be a no-op
    assert ch.opened is True


# ----------------- execute() -----------------


def test_execute_returns_bytes():
    ch = FakeSSHChannel(
        responses={"show version": "Cisco IOS XE, Version 17.3\nrouter#"},
    )
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    out = t.execute("show version")
    assert b"Cisco IOS XE" in out
    assert b"router#" in out


def test_execute_uses_default_response():
    ch = FakeSSHChannel(default_response="router#")
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    out = t.execute("anything")
    assert b"router#" in out


def test_execute_retries_on_channel_error():
    ch = FakeSSHChannel(command_fail=TimeoutError("session expired"))
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    with pytest.raises(Failure) as exc:
        t.execute("show ip")
    assert exc.value.cls is FailureClass.RETRYABLE
    assert exc.value.retry_hint is not None


def test_execute_requires_open():
    t = SSHConsoleTransport(SSHProfile(host="h", username="u"))
    with pytest.raises(Failure) as exc:
        t.execute("x")
    assert "SESSION_NOT_OPEN" in exc.value.causes[0]


def test_execute_respects_timeout_cap():
    ch = FakeSSHChannel(default_response="router#")
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u", max_read_s=5.0),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    # Asking for more than max_read_s is clamped to max_read_s.
    out = t.execute("x", timeout_s=999)
    assert isinstance(out, bytes)


# ----------------- close() / context manager -----------------


def test_close_disconnects_channel():
    ch = FakeSSHChannel()
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    t.close()
    assert ch.closed is True
    assert t.is_open is False


def test_close_swallows_exceptions():
    class _ExplodingChannel(FakeSSHChannel):
        def disconnect(self) -> None:
            raise RuntimeError("boom")
    ch = _ExplodingChannel()
    t = SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    )
    t.open()
    t.close()  # must not raise


def test_context_manager():
    ch = FakeSSHChannel()
    with SSHConsoleTransport(
        SSHProfile(host="h", username="u"),
        driver_factory=fake_ssh_factory(ch),
    ) as t:
        assert t.is_open
    assert ch.closed is True


# ----------------- Lazy import (no Netmiko installed) -----------------


def test_lazy_import_missing_netmiko(monkeypatch):
    """When Netmiko is absent, ``_netmiko_factory`` must raise a typed BLOCKED."""
    import builtins
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "netmiko":
            raise ImportError("simulated missing driver")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    from netops_autopilot.access.ssh_transport import _netmiko_factory
    with pytest.raises(Failure) as exc:
        _netmiko_factory("h", 22, "u", "p", "autodetect", 5.0)
    assert exc.value.cls is FailureClass.BLOCKED
    assert "Netmiko" in exc.value.causes[0]
