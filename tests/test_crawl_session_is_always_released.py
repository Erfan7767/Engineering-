"""A crawl session to a real device is released on every exit path.

`DiscoveryCrawlEngine._crawl_device()` opened a management session and closed
it at two explicit points: the early `NO_PLAN` return, and the end of the
normal path. There was no `finally`. Any failure raised in between — a ledger
write failing, a claim or twin admission raising, a parser bug — propagated out
of the method with the session still open.

Measured before the fix: forcing `LedgerStore.append_observation` to raise left
`session.closed == False`. On real hardware that holds a VTY line for the life
of the process. Cisco's default `line vty 0 4` is five sessions in total, so a
crawl that fails repeatedly against a flaky ledger eventually locks the
operator out of the very device the platform is supposed to be managing — and
does it silently, because the session is invisible in the report.

Closing is now in a `finally`, and a transport that itself refuses to close is
recorded as a typed reason on the device rather than raised over whatever
failure is already in flight.
"""

from __future__ import annotations

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.engines.discovery_crawl import DeviceStatus
from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir
from tests.support.loopback import LoopbackSession
from tests.test_discovery_crawl import (
    BACK_TABLE,
    BACK_VERSION,
    READ_ONLY,
    ScriptedFactory,
    _engine,
)

FIXTURES = simfabric_fixtures_dir()
ALLOWLIST = CommandAllowlist(tuple(
    AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY))

#: A neighbour that advertises no platform this codebase recognises, so the
#: crawl plan for it is empty and the early NO_PLAN return is taken.
NO_PLATFORM = b"""Capability codes:
    (R) Router, (B) Bridge

------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 1234.5678.9abc
Port id: Gi0/9
Port Description: Gi0/9
System Name: MYSTERY-BOX
System Description:
Acme Custom NOS 3.1 (build 20240101)
Time remaining: 95 seconds
Management Addresses:
    IP: 10.99.0.77

Total entries displayed: 1
"""


class _RefusingClose(LoopbackSession):
    """A transport that will not let go — SSH drops, serial hangs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.close_attempts = 0

    def close(self):
        self.close_attempts += 1
        raise OSError("transport refused to close")


def _seed_session(lldp=None, session_cls=LoopbackSession):
    return session_cls({
        "show version": (FIXTURES / "cisco_iosxe" / "show_version.txt").read_bytes(),
        "show lldp neighbors detail": (
            lldp if lldp is not None
            else (FIXTURES / "cisco_iosxe"
                  / "show_lldp_neighbors_detail.txt").read_bytes()),
        "show cdp neighbors detail": (
            FIXTURES / "cisco_iosxe" / "show_cdp_neighbors_detail.txt").read_bytes(),
    })


def _factory(seed_session, neighbour_session=None):
    return ScriptedFactory(scripts={
        "core-sw1": seed_session,
        "core-sw2": neighbour_session or LoopbackSession({
            "show version": BACK_VERSION,
            "show lldp neighbors detail": BACK_TABLE,
            "show cdp neighbors detail": b"",
        }),
        "mystery-box": LoopbackSession({
            "show version": BACK_VERSION,
            "show lldp neighbors detail": b"",
            "show cdp neighbors detail": b"",
        }),
    })


def _crawl(factory):
    engine, store, _twin, _le, _al = _engine(factory)
    report = engine.crawl(
        seed_ref="core-sw1", seed_family="cisco/ios-xe", session_factory=factory,
        allowlist_of=lambda family: ALLOWLIST)
    return report, store


# ======================================================= every exit path closes
def test_the_session_is_closed_on_the_normal_path():
    seed = _seed_session()
    factory = _factory(seed)
    report, _store = _crawl(factory)
    by_ref = {d.device_ref: d for d in report.devices}
    assert by_ref["core-sw1"].status is DeviceStatus.COMPLETE
    assert seed.closed is True
    assert factory._scripts["core-sw2"].closed is True


def test_the_session_is_closed_when_there_is_no_crawl_plan():
    """The early return must not be the one path that forgets."""
    seed = _seed_session(lldp=NO_PLATFORM)
    factory = _factory(seed)
    report, _store = _crawl(factory)
    by_ref = {d.device_ref: d for d in report.devices}
    assert by_ref["mystery-box"].status is DeviceStatus.NO_PLAN
    assert factory._scripts["mystery-box"].closed is True
    assert seed.closed is True


def test_the_session_is_closed_when_the_crawl_fails_midway():
    """The leak this file exists for: a ledger write fails after the session
    was opened, and the failure still has to reach the caller unchanged."""
    seed = _seed_session()
    factory = _factory(seed)
    engine, store, _twin, _le, _al = _engine(factory)

    calls = {"n": 0}
    real = store.append_observation

    def failing_write(observation):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("ledger write failed: disk full")
        return real(observation)

    store.append_observation = failing_write
    try:
        with pytest.raises(RuntimeError, match="disk full"):
            engine.crawl(seed_ref="core-sw1", seed_family="cisco/ios-xe",
                         session_factory=factory, allowlist_of=lambda f: ALLOWLIST)
    finally:
        store.append_observation = real

    assert calls["n"] >= 2, "the failure must actually have been triggered"
    assert seed.closed is True, "the transport was left open on the device"


# ============================================ a transport that will not let go
def test_a_transport_that_refuses_to_close_is_reported_not_fatal():
    """The device still has to be reported on. A close failure is a fact about
    the transport, not a reason to lose the crawl — and it must not be raised
    over a failure that is already in flight."""
    seed = _seed_session(session_cls=_RefusingClose)
    factory = _factory(seed)
    report, _store = _crawl(factory)

    assert seed.close_attempts == 1
    by_ref = {d.device_ref: d for d in report.devices}
    seed_result = by_ref["core-sw1"]
    # the crawl result survived, and the close failure is stated
    assert seed_result.status in (DeviceStatus.COMPLETE, DeviceStatus.PARTIAL)
    assert any(r.startswith("SESSION_CLOSE_FAILED")
               for r in seed_result.rejection_reasons), seed_result.rejection_reasons
    assert any("transport refused to close" in r
               for r in seed_result.rejection_reasons), seed_result.rejection_reasons


def test_a_close_failure_does_not_mask_the_real_failure():
    """Two faults at once: the ledger fails AND the transport will not close.
    The operator must see the ledger failure, not the close failure."""
    seed = _seed_session(session_cls=_RefusingClose)
    factory = _factory(seed)
    engine, store, _twin, _le, _al = _engine(factory)

    calls = {"n": 0}
    real = store.append_observation

    def failing_write(observation):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("ledger write failed: disk full")
        return real(observation)

    store.append_observation = failing_write
    try:
        with pytest.raises(RuntimeError, match="disk full"):
            engine.crawl(seed_ref="core-sw1", seed_family="cisco/ios-xe",
                         session_factory=factory, allowlist_of=lambda f: ALLOWLIST)
    finally:
        store.append_observation = real

    assert seed.close_attempts == 1, "close was still attempted"
