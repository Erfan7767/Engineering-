"""A neighbour discovered by LLDP alone must still be crawlable.

`show lldp neighbors detail` carries the neighbour's own platform string in
`System Description:` — on the FOLLOWING line, which a line-based key/value
scan drops. The parser left `platform` as None for every LLDP row, even though
`platform` is a declared field of the entry schema ("advertised platform
string, or None"). CDP's parser did fill it, so the hole was invisible in every
fixture that answered both protocols.

The consequence was measured, not inferred: with `show cdp neighbors detail`
returning nothing — which is what `no cdp run` produces, a routine hardening
step — the same neighbour went from `COMPLETE (3/3 commands)` to
`NO_PLAN (0 commands)`. The device was there, it answered the management
session, and the platform collected nothing from it and could never have
configured it. `platform_family_hint()` had nothing to work with, so the family
stayed UNKNOWN and `plan_for()` returned an empty plan.

And the map did not say why: `NO_PLAN` produced no gap line at all, so the
device appeared as `IDENTITY_INCOMPLETE` — the symptom, with the cause
(`NO_CRAWL_PLAN`) sitting unread in `rejection_reasons`. An operator could not
tell a device that refused to talk from one the platform had no plan for.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.collector import Collector, SessionLockManager
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.engines.claim_factory import ClaimFactory
from netops_autopilot.engines.discovery_crawl import (
    DeviceStatus,
    DiscoveryCrawlEngine,
)
from netops_autopilot.engines.link_evidence import LinkEvidenceEngine
from netops_autopilot.engines.topology_map import TopologyMapEngine
from netops_autopilot.fsm.link_fsm import build_link_fsm
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.parsers.catalog import default_registry
from netops_autopilot.parsers.neighbor_parsers import (
    CiscoIosXeLldpNeighborsDetailParser,
)
from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir
from netops_autopilot.twin.twin import DigitalTwin
from tests.support.loopback import LoopbackSession
from tests.test_discovery_crawl import BACK_TABLE, BACK_VERSION, ScriptedFactory

FIXTURES = simfabric_fixtures_dir()
READ_ONLY = (
    "show version", "show lldp neighbors detail", "show cdp neighbors detail",
)
ALLOWLIST = CommandAllowlist(tuple(
    AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY))

#: A neighbour whose System Description names no platform this codebase knows.
UNKNOWN_NOS = b"""Capability codes:
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


def _seed_session(cdp: bytes, lldp=None) -> LoopbackSession:
    return LoopbackSession({
        "show version": (FIXTURES / "cisco_iosxe" / "show_version.txt").read_bytes(),
        "show lldp neighbors detail": (
            lldp if lldp is not None
            else (FIXTURES / "cisco_iosxe" / "show_lldp_neighbors_detail.txt").read_bytes()),
        "show cdp neighbors detail": cdp,
    })


def _engine(collector_allowlist=ALLOWLIST):
    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    now = datetime(2026, 9, 13, 12, 0, 0, tzinfo=timezone.utc)
    counters = CounterCollector()
    twin = DigitalTwin(store, counters)
    engine = DiscoveryCrawlEngine(
        store=store, twin=twin,
        collector=Collector(
            store=store, key_id=key, allowlist=collector_allowlist,
            time_authority=TimeAuthority(clock=lambda: now),
            locks=SessionLockManager(),
            default_budget=CommandBudget(max_retries=0)),
        parsers=default_registry(),
        link_engine=LinkEvidenceEngine(
            lambda: build_link_fsm(recorder=store, counters=counters)),
        claim_factory=ClaimFactory(store, default_registry()))
    return engine, twin


def _crawl(cdp: bytes, lldp=None, collector_allowlist=ALLOWLIST):
    factory = ScriptedFactory(
        scripts={
            "core-sw1": _seed_session(cdp, lldp),
            "core-sw2": LoopbackSession({
                "show version": BACK_VERSION,
                "show lldp neighbors detail": BACK_TABLE,
                "show cdp neighbors detail": b"",
            }),
            # Reachable, so that a device named by UNKNOWN_NOS fails on the
            # command plan rather than on the session.
            "mystery-box": LoopbackSession({
                "show version": BACK_VERSION,
                "show lldp neighbors detail": b"",
                "show cdp neighbors detail": b"",
            }),
        },
        refuse={"access-sw1": ("AUTH_REFUSED: default credentials rejected "
                               "(ACCESS_LIMITED)",)})
    engine, twin = _engine(collector_allowlist)
    report = engine.crawl(
        seed_ref="core-sw1", seed_family="cisco/ios-xe", session_factory=factory,
        allowlist_of=lambda family: ALLOWLIST)
    return report, TopologyMapEngine(twin).build(report)


CDP_ON = (FIXTURES / "cisco_iosxe" / "show_cdp_neighbors_detail.txt").read_bytes()
CDP_OFF = b""


# =============================================== 1. the parser keeps the field
def test_lldp_carries_the_platform_the_neighbour_advertised():
    """The device states it; dropping it is not conservative, it is lossy."""
    raw = (FIXTURES / "cisco_iosxe" / "show_lldp_neighbors_detail.txt").read_bytes()
    rows = next(o for o in CiscoIosXeLldpNeighborsDetailParser().parse(raw, "raw")
                if o.field == "neighbor_table_lldp").value
    by_name = {r["neighbor_id"]: r["platform"] for r in rows}
    assert by_name["CORE-SW2.lab"] == (
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
        "(CAT9K_IOSXE), Version 17.09.04a")
    assert by_name["ACCESS-SW1.lab"] == (
        "Cisco IOS Software, C9200L Software (PPC_LINUX_IOSD-UNIVERSALK9-M), "
        "Version 17.12.03")
    assert all(p for p in by_name.values()), by_name


def test_an_empty_system_description_does_not_swallow_the_next_line():
    """The value sits on the following line, so an absent description must not
    be filled with the next record's key line."""
    raw = (b"------------------------------------------------\n"
           b"Local Intf: Gi1/0/1\n"
           b"Chassis id: 0011.2233.4455\n"
           b"Port id: Gi0/1\n"
           b"System Name: QUIET-SW\n"
           b"System Description:\n"
           b"Time remaining: 100 seconds\n"
           b"Management Addresses:\n"
           b"    IP: 10.99.0.3\n\n"
           b"Total entries displayed: 1\n")
    rows = next(o for o in CiscoIosXeLldpNeighborsDetailParser().parse(raw, "raw")
                if o.field == "neighbor_table_lldp").value
    assert rows[0]["neighbor_id"] == "QUIET-SW"
    assert rows[0]["platform"] is None, rows[0]


# ================================================== 2. and the crawl can use it
def test_a_neighbour_is_crawlable_when_cdp_is_disabled():
    """`no cdp run` is hardening, not an excuse to stop discovering."""
    report, _topo = _crawl(CDP_OFF)
    by_ref = {d.device_ref: d for d in report.devices}
    assert by_ref["core-sw2"].status is DeviceStatus.COMPLETE, (
        by_ref["core-sw2"].status, by_ref["core-sw2"].rejection_reasons)
    collected, planned = by_ref["core-sw2"].counts()
    assert planned == len(READ_ONLY) and collected == planned, (collected, planned)


def test_disabling_cdp_does_not_change_what_is_discovered():
    """Same physical network, same answer, whichever courtesy protocol is on."""
    on, _t1 = _crawl(CDP_ON)
    off, _t2 = _crawl(CDP_OFF)
    assert ({d.device_ref: d.status.value for d in on.devices}
            == {d.device_ref: d.status.value for d in off.devices}), (
        {d.device_ref: d.status.value for d in on.devices},
        {d.device_ref: d.status.value for d in off.devices})
    assert on.totals["commands_collected"] == off.totals["commands_collected"]


# ============================================== 3. and the map states the cause
def test_a_device_with_no_crawl_plan_says_why():
    """NO_PLAN used to render only as IDENTITY_INCOMPLETE — the symptom with
    the cause left unread in rejection_reasons."""
    lldp = UNKNOWN_NOS
    report, topo = _crawl(CDP_OFF, lldp=lldp)
    by_ref = {d.device_ref: d for d in report.devices}
    assert "mystery-box" in by_ref, sorted(by_ref)
    assert by_ref["mystery-box"].status is DeviceStatus.NO_PLAN
    gap = [g for g in topo.gaps if g.startswith("DEVICE_NOT_CRAWLABLE mystery-box")]
    assert gap, topo.gaps
    assert "NO_CRAWL_PLAN" in gap[0], gap
    # the reason is specific: the family, not a shrug
    assert "UNKNOWN" in gap[0], gap


def test_a_device_the_collector_refused_says_why():
    """A plan existed but nothing could be collected — a different failure from
    having no plan, and it must not read the same as success."""
    # The plan comes from `allowlist_of`, the collector enforces its own; a
    # mismatch between them is a real misconfiguration, and every command is
    # then refused before it reaches the device.
    report, topo = _crawl(CDP_ON, collector_allowlist=CommandAllowlist(()))
    by_ref = {d.device_ref: d for d in report.devices}
    blocked = [r for r, d in by_ref.items()
               if d.status is DeviceStatus.BLOCKED]
    assert blocked, {r: d.status.value for r, d in by_ref.items()}
    ref = sorted(blocked)[0]
    assert by_ref[ref].counts() == (0, len(READ_ONLY))
    gap = [g for g in topo.gaps if g.startswith(f"DEVICE_BLOCKED {ref}")]
    assert gap, topo.gaps
