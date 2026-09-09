"""Discovery Crawl Engine: the multi-device evidence walk (§10).

Topology under test (simulated sessions, deterministic):

    core-sw1 (SEED, direct) ──LLDP── core-sw2 (reachable, names back)
        └──LLDP one-sided──> access-sw1 (session factory REFUSES: UNREACHABLE)

Proves: frontier expansion, per-device T4 n/N, FSM-4 ladder (ONE_SIDED →
PROBABLE only on bidirectional match), claim/Twin admission via Claim
Factory, deterministic replay.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.collector import Collector, SessionLockManager
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.engines.claim_factory import ClaimFactory
from netops_autopilot.engines.discovery_crawl import (
    CommandStatus,
    DeviceStatus,
    DiscoveryCrawlEngine,
)
from netops_autopilot.engines.link_evidence import LinkEvidenceEngine
from netops_autopilot.fsm import link_fsm as lf
from netops_autopilot.fsm.link_fsm import build_link_fsm
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.parsers.catalog import default_registry
from netops_autopilot.twin.twin import DigitalTwin
from tests.support.loopback import LoopbackSession

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "golden"
NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

READ_ONLY = (
    "show version", "show lldp neighbors detail", "show cdp neighbors detail",
)

BACK_TABLE = b"""Capability codes:
    (R) Router, (B) Bridge

------------------------------------------------
Local Intf: Gi0/1
Chassis id: 0011.2233.4455
Port id: Gi1/0/1
Port Description: GigabitEthernet1/0/1
System Name: CORE-SW1
System Description:
Cisco IOS Software
Time remaining: 100 seconds
Management Addresses:
    IP: 10.99.0.1

Total entries displayed: 1
"""

BACK_VERSION = b"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software
cisco C9300-48P (ARM) processor
CORE-SW2 uptime is 1 day, 2 hours
System serial number           : FOC1234X9YZ
Configuration register is 0x2102
"""


class ScriptedFactory:
    """Deterministic SessionFactory: scripts per device, typed refusals."""

    def __init__(self, scripts: dict[str, LoopbackSession], refuse: dict[str, tuple[str, ...]] | None = None) -> None:
        self._scripts = scripts
        self._refuse = dict(refuse or {})
        self.opened: list[str] = []

    def open(self, device_ref: str, mgmt_hints: tuple[str, ...]):
        self.opened.append(device_ref)
        if device_ref in self._refuse:
            raise Failure(cls=FailureClass.BLOCKED, causes=self._refuse[device_ref])
        session = self._scripts.get(device_ref)
        if session is None:
            raise Failure(cls=FailureClass.BLOCKED, causes=(f"NO_ROUTE_KNOWN: {device_ref} has no session script",))
        return session


def _engine(seed_session_factory):
    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    allowlist = CommandAllowlist(tuple(
        AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY))
    registry = default_registry()
    collector = Collector(
        store=store, key_id=key, allowlist=allowlist,
        time_authority=TimeAuthority(clock=lambda: NOW), locks=SessionLockManager(),
        default_budget=CommandBudget(max_retries=0))
    counters = CounterCollector()
    twin = DigitalTwin(store, counters)
    link_engine = LinkEvidenceEngine(lambda: build_link_fsm(recorder=store, counters=counters))
    engine = DiscoveryCrawlEngine(
        store=store, twin=twin, collector=collector, parsers=registry,
        link_engine=link_engine, claim_factory=ClaimFactory(store, registry))
    return engine, store, twin, link_engine, allowlist


def _seed_session() -> LoopbackSession:
    def fx(name: str) -> bytes:
        return (FIXTURES / "cisco_iosxe" / f"{name}.txt").read_bytes()
    return LoopbackSession({
        "show version": fx("show_version"),
        "show lldp neighbors detail": fx("show_lldp_neighbors_detail"),
        "show cdp neighbors detail": fx("show_cdp_neighbors_detail"),
    })


def test_crawl_expands_frontier_and_classifies():
    factory = ScriptedFactory(
        scripts={
            "core-sw1": _seed_session(),
            "core-sw2": LoopbackSession({
                "show version": BACK_VERSION,
                "show lldp neighbors detail": BACK_TABLE,
                "show cdp neighbors detail": b"",
            }),
        },
        refuse={"access-sw1": ("AUTH_REFUSED: default credentials rejected (ACCESS_LIMITED)",)},
    )
    engine, store, twin, link_engine, allowlist = _engine(factory)

    report = engine.crawl(
        seed_ref="core-sw1", seed_family="cisco/ios-xe",
        session_factory=factory, allowlist_of=lambda family: allowlist)

    # Devices: seed COMPLETE, reachable neighbor COMPLETE, refused neighbor UNREACHABLE.
    by_ref = {d.device_ref: d for d in report.devices}
    assert set(by_ref) == {"core-sw1", "core-sw2", "access-sw1"}
    assert by_ref["core-sw1"].status is DeviceStatus.COMPLETE
    assert by_ref["core-sw2"].status is DeviceStatus.COMPLETE
    assert by_ref["access-sw1"].status is DeviceStatus.UNREACHABLE
    assert any("AUTH_REFUSED" in reason for reason in by_ref["access-sw1"].rejection_reasons)

    # T4 n/N per device: seed planned=3 collected=3; core-sw2 cdp returns
    # empty bytes ⇒ parser MISSING fields but the command COLLECTED (n=3/3).
    assert by_ref["core-sw1"].counts() == (3, 3)
    assert by_ref["core-sw2"].counts() == (3, 3)
    assert by_ref["access-sw1"].counts() == (0, 0)

    # Identity is evidence-tagged, never invented.
    identity = by_ref["core-sw1"].identity
    assert identity.vendor_family == "cisco/ios-xe"
    assert identity.model == "C8300-1N-4T"
    assert identity.version == "17.09.04a"
    assert identity.serial == "DOG2734L0XX"
    assert identity.evidence_obs_ids  # every fact carries obs ids

    # Twin holds the neighbor table claim (admitted through the guard).
    entity = twin.entity("DEVICE", "core-sw1")
    assert entity is not None and "neighbor_table_lldp" in entity.fields and "neighbor_table_cdp" in entity.fields
    assert by_ref["core-sw1"].claim_admitted > 0

    # Links: seed↔core-sw2 reached the PASSIVE ceiling PROBABLE
    # (bidirectional match); seed↔access-sw1 stayed ONE_SIDED.
    states = {link.link_id: link.fsm4_state for link in report.links}
    assert lf.DIRECT_NEIGHBOR_PROBABLE in states.values()
    assert lf.ONE_SIDED in states.values()
    probable = [l for l in report.links if l.fsm4_state == lf.DIRECT_NEIGHBOR_PROBABLE][0]
    ends = sorted([probable.endpoint_a.key(), probable.endpoint_b.key()])
    assert ends == ["core-sw1|Gi1/0/1", "core-sw2|Gi0/1"]
    assert probable.evidence_obs_ids

    # Ledger integrity over the whole crawl.
    store.integrity_self_test()
    assert store.event_count() == 6  # 3 commands × 2 reached devices

    # Deterministic totals.
    assert report.totals["commands_collected"] == 6
    assert report.totals["device_status"] == {"COMPLETE": 2, "UNREACHABLE": 1}
    assert report.frontier_exhausted


def test_crawl_no_plan_is_typed_not_guessed():
    factory = ScriptedFactory(scripts={"mystery": LoopbackSession({})})
    engine, store, twin, link_engine, allowlist = _engine(factory)
    report = engine.crawl(
        seed_ref="mystery", seed_family="UNKNOWN",
        session_factory=factory, allowlist_of=lambda family: CommandAllowlist(()))
    device = report.devices[0]
    assert device.status is DeviceStatus.NO_PLAN
    assert any("NO_CRAWL_PLAN" in r for r in device.rejection_reasons)


def test_broken_transport_is_visible_partial_never_silent():
    flaky = LoopbackSession(
        outputs={
            "show version": (FIXTURES / "cisco_iosxe" / "show_version.txt").read_bytes(),
            "show cdp neighbors detail": b"",
        },
        fail_times={})  # missing key: output empty; still COLLECTED
    session = LoopbackSession({
        "show version": (FIXTURES / "cisco_iosxe" / "show_version.txt").read_bytes(),
        "show lldp neighbors detail": LoopbackSession.TIMEOUT_SENTINEL.encode(),
        "show cdp neighbors detail": b"",
    })
    factory = ScriptedFactory(scripts={"sw": session})
    engine, store, twin, link_engine, allowlist = _engine(factory)
    report = engine.crawl(
        seed_ref="sw", seed_family="cisco/ios-xe",
        session_factory=factory, allowlist_of=lambda family: allowlist)
    device = report.devices[0]
    assert device.status is DeviceStatus.PARTIAL
    collected, planned = device.counts()
    assert (collected, planned) == (2, 3)
    failed = [c for c in device.commands if c.status is CommandStatus.RETRYABLE]
    assert len(failed) == 1 and "TRANSPORT_ERROR" in failed[0].causes[0]
