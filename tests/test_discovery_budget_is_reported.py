"""A discovery budget that stops the walk must say so — not look complete.

`DiscoveryCrawlEngine.crawl()` is bounded by `max_devices` and
`max_l3_probes`, and `autopilot/orchestrator.py` calls it without passing
either, so the defaults (256 / 32) are what every real run uses. On a network
large enough to hit them, two silent truncations were possible:

1. The CDP/LLDP frontier loop `while frontier and len(visited) < max_devices`
   simply stopped. A device that a neighbour had *named* — real evidence that
   it exists — vanished from the report entirely.
2. `CrawlReport.l3_endpoints` faithfully recorded every endpoint the L3 probe
   budget refused (see `test_the_probe_budget_records_what_it_did_not_probe`),
   but `TopologyMapEngine` never read that field, so the map never mentioned
   it.

In both cases the only trace was `CrawlReport.frontier_exhausted`, which no
code outside `discovery_crawl.py` reads. The operator got a topology map with
no gap lines about the missing equipment — a network that looked discovered
when it had only been partly looked at. That is the "ignoring things" failure
the platform is not allowed to have, so what a budget refused is now recorded
as a `NOT_PROBED` device / unprobed endpoint *and* surfaced as a
`DISCOVERY_TRUNCATED` gap on the map.

`NOT_PROBED` is deliberately distinct from `UNREACHABLE`: unreachable means a
session was attempted and refused (something is known — the cause); not probed
means nothing was attempted, so nothing at all is known.
"""

from __future__ import annotations

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.collector import Collector, SessionLockManager
from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure, FailureClass
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
from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir
from netops_autopilot.twin.twin import DigitalTwin
from tests.support.loopback import LoopbackSession
from tests.support.simfabric import SimFabricFactory, make_ledger_stack

FIXTURES = simfabric_fixtures_dir()
READ_ONLY = (
    "show version", "show lldp neighbors detail", "show cdp neighbors detail",
)


# ==================================================================== harness
class ScriptedFactory:
    """Deterministic SessionFactory that records every open() attempt.

    `opened` is the point of the harness: it is what separates UNREACHABLE
    (attempted, refused) from NOT_PROBED (never attempted at all).
    """

    def __init__(self, scripts, refuse=None):
        self._scripts = scripts
        self._refuse = dict(refuse or {})
        self.opened: list[str] = []

    def open(self, device_ref, mgmt_hints):
        self.opened.append(device_ref)
        if device_ref in self._refuse:
            raise Failure(cls=FailureClass.BLOCKED, causes=self._refuse[device_ref])
        session = self._scripts.get(device_ref)
        if session is None:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"NO_ROUTE_KNOWN: {device_ref} has no session script",))
        return session


def _engine(factory):
    from datetime import datetime, timezone

    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    allowlist = CommandAllowlist(tuple(
        AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY))
    registry = default_registry()
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    collector = Collector(
        store=store, key_id=key, allowlist=allowlist,
        time_authority=TimeAuthority(clock=lambda: now), locks=SessionLockManager(),
        default_budget=CommandBudget(max_retries=0))
    counters = CounterCollector()
    twin = DigitalTwin(store, counters)
    link_engine = LinkEvidenceEngine(
        lambda: build_link_fsm(recorder=store, counters=counters))
    engine = DiscoveryCrawlEngine(
        store=store, twin=twin, collector=collector, parsers=registry,
        link_engine=link_engine, claim_factory=ClaimFactory(store, registry))
    return engine, twin


def _seed_session():
    def fx(name):
        return (FIXTURES / "cisco_iosxe" / f"{name}.txt").read_bytes()
    return LoopbackSession({
        "show version": fx("show_version"),
        "show lldp neighbors detail": fx("show_lldp_neighbors_detail"),
        "show cdp neighbors detail": fx("show_cdp_neighbors_detail"),
    })


BACK_VERSION = b"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software
cisco C9300-48P (ARM) processor
CORE-SW2 uptime is 1 day, 2 hours
System serial number           : FOC1234X9YZ
Configuration register is 0x2102
"""

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


# core-sw2 naming a device the seed never mentioned, so that device can only
# enter the frontier from the *last* wave the budget allowed.
BACK_TABLE_TWO = BACK_TABLE.replace(
    b"Total entries displayed: 1",
    b"""------------------------------------------------
Local Intf: Gi0/2
Chassis id: aabb.ccdd.eeff
Port id: Gi1/0/24
Port Description: GigabitEthernet1/0/24
System Name: DIST-SW1
System Description:
Cisco IOS Software
Time remaining: 90 seconds
Management Addresses:
    IP: 10.99.0.7

Total entries displayed: 2""")


def _three_device_factory(back_table=BACK_TABLE):
    """seed core-sw1 ── names ──> core-sw2 (works) and access-sw1 (refuses)."""
    return ScriptedFactory(
        scripts={"core-sw1": _seed_session(),
                 "core-sw2": LoopbackSession({
                     "show version": BACK_VERSION,
                     "show lldp neighbors detail": back_table,
                     "show cdp neighbors detail": b""})},
        refuse={"access-sw1": ("AUTH_REFUSED: default credentials rejected "
                               "(ACCESS_LIMITED)",)})


def _crawl(max_devices=256, max_l3_probes=32, back_table=BACK_TABLE):
    factory = _three_device_factory(back_table)
    engine, twin = _engine(factory)
    report = engine.crawl(
        seed_ref="core-sw1", seed_family="cisco/ios-xe", session_factory=factory,
        allowlist_of=lambda family: CommandAllowlist(tuple(
            AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY)),
        max_devices=max_devices, max_l3_probes=max_l3_probes)
    return report, TopologyMapEngine(twin).build(report), factory


# ============================================ 1. the device budget is recorded
def test_a_device_budget_records_the_device_it_refused_to_crawl():
    """A neighbour named core-sw2; the budget meant it was never crawled.

    Before this was fixed the device simply did not appear in the report: three
    pieces of equipment existed, the crawl returned two, and nothing said so.
    """
    report, _map, factory = _crawl(max_devices=2)
    by_ref = {d.device_ref: d for d in report.devices}

    assert "core-sw2" in by_ref, sorted(by_ref)
    refused = by_ref["core-sw2"]
    assert refused.status is DeviceStatus.NOT_PROBED
    assert refused.rejection_reasons, "a budget refusal must carry a reason"
    reason = refused.rejection_reasons[0]
    assert reason.startswith("NOT_PROBED:"), reason
    assert "device budget 2 reached" in reason, reason
    # the total reflects it too, so a summary cannot hide it
    assert report.totals["device_status"]["NOT_PROBED"] == 1


def test_not_probed_is_not_unreachable_nothing_was_attempted():
    """The two statuses must stay distinguishable — they mean different things.

    access-sw1 was opened and refused (UNREACHABLE, cause known). core-sw2 was
    never opened at all (NOT_PROBED, nothing known). Conflating them would tell
    an operator a device rejected credentials when in fact nobody knocked.
    """
    report, _map, factory = _crawl(max_devices=2)
    by_ref = {d.device_ref: d for d in report.devices}

    assert "access-sw1" in factory.opened
    assert by_ref["access-sw1"].status is DeviceStatus.UNREACHABLE

    assert "core-sw2" not in factory.opened, factory.opened
    assert by_ref["core-sw2"].status is DeviceStatus.NOT_PROBED
    assert by_ref["core-sw2"].commands == []
    assert by_ref["core-sw2"].identity is None


def test_a_neighbour_found_in_the_final_wave_is_not_lost():
    """The budget can close between waves, not only inside one.

    With `max_devices=3`: seed-01 and access-sw1 and core-sw2 fill the budget,
    and core-sw2 is the one that names dist-sw1. dist-sw1 therefore only ever
    exists in the *next* frontier — the wave the loop never entered. Recording
    refusals inside the loop is not enough; whatever was still queued when the
    loop condition failed has to be captured too, or that device disappears
    with no trace at all.
    """
    report, topo, factory = _crawl(max_devices=3, back_table=BACK_TABLE_TWO)
    by_ref = {d.device_ref: d for d in report.devices}

    # the budget really did close on a full wave, not mid-wave
    assert by_ref["core-sw2"].status is DeviceStatus.COMPLETE
    assert "dist-sw1" not in factory.opened, factory.opened

    assert "dist-sw1" in by_ref, sorted(by_ref)
    assert by_ref["dist-sw1"].status is DeviceStatus.NOT_PROBED
    assert "device budget 3 reached" in by_ref["dist-sw1"].rejection_reasons[0]
    assert any(g.startswith("DISCOVERY_TRUNCATED dist-sw1:") for g in topo.gaps), topo.gaps


def test_the_device_budget_is_not_hit_by_default():
    """Guard against a false alarm: at the default budget nothing is refused."""
    report, _map, factory = _crawl()
    statuses = {d.device_ref: d.status for d in report.devices}
    assert statuses == {
        "core-sw1": DeviceStatus.COMPLETE,
        "core-sw2": DeviceStatus.COMPLETE,
        "access-sw1": DeviceStatus.UNREACHABLE,
    }, statuses
    assert "NOT_PROBED" not in report.totals["device_status"]
    assert "core-sw2" in factory.opened


# ================================================== 2. and it reaches the map
def test_a_truncated_crawl_is_visible_on_the_topology_map():
    """The map is what the operator reads; a truncation must appear as a gap."""
    report, topo, _factory = _crawl(max_devices=2)
    truncated = [g for g in topo.gaps if g.startswith("DISCOVERY_TRUNCATED")]
    assert truncated, topo.gaps
    assert any(g.startswith("DISCOVERY_TRUNCATED core-sw2:") for g in truncated), truncated
    assert any("device budget 2 reached" in g for g in truncated), truncated
    # ...and it survives serialisation, which is what the API/UI consume
    assert any("core-sw2" in g for g in topo.to_dict()["gaps"]), topo.to_dict()["gaps"]


def test_an_untruncated_crawl_claims_no_truncation():
    """The gap must be earned, not emitted always — otherwise it is noise."""
    _report, topo, _factory = _crawl()
    assert not [g for g in topo.gaps if g.startswith("DISCOVERY_TRUNCATED")], topo.gaps
    # the map still carries its other honest gaps
    assert any(g.startswith("DEVICE_UNREACHABLE access-sw1") for g in topo.gaps)


# ============================================ 3. the L3 probe budget likewise
def _fabric_crawl(max_l3_probes):
    """A real crawl over the simulated fabric, at a chosen L3 probe budget.

    The orchestrator pins `max_l3_probes` at its default, so the same engine
    instance is driven directly with a budget that actually refuses — the
    collector, parsers, ledger and allowlists are the ones the real run built.
    """
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y",
                                    intent="branch office with VoIP")),
        time_authority=time_auth)
    engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
               mgmt_session_factory=fabric, port="SIM0", execute=False)

    seed_session = fabric.probe("SIM0")[0]

    class _Factory:
        def open(self, device_ref, hints):
            if device_ref == "seed-01":
                return seed_session
            return fabric.open(device_ref, hints)

    report = engine.crawl.crawl(
        seed_ref="seed-01", seed_family="cisco/ios-xe", session_factory=_Factory(),
        allowlist_of=lambda fam: engine.catalog_allowlists.get(
            fam, CommandAllowlist(())),
        max_l3_probes=max_l3_probes)
    return report, TopologyMapEngine(engine.twin).build(report)


def test_an_unprobed_l3_endpoint_reaches_the_map():
    """10.99.0.9 never advertises; ARP+MAC prove it exists on seed-01:Gi1/0/9.

    With the probe budget closed it is recorded on the crawl report but was
    invisible to the map, so the operator saw a topology missing a device that
    the platform demonstrably knew about.
    """
    report, topo = _fabric_crawl(max_l3_probes=0)

    endpoints = [e for e in report.l3_endpoints if e.ip == "10.99.0.9"]
    assert endpoints, [e.ip for e in report.l3_endpoints]
    assert endpoints[0].probed is False

    truncated = [g for g in topo.gaps if g.startswith("DISCOVERY_TRUNCATED l3-")]
    assert truncated, topo.gaps
    line = truncated[0]
    assert line.startswith("DISCOVERY_TRUNCATED l3-10.99.0.9:"), line
    assert "L3 probe budget 0 reached" in line, line
    # the evidence that the device exists is carried, not just the refusal
    assert "9999.8888.7777" in line, line
    assert "seed-01:Gi1/0/9" in line, line


def test_a_probed_l3_endpoint_raises_no_truncation_gap():
    """At the default budget the same endpoint is probed and must not alarm."""
    report, topo = _fabric_crawl(max_l3_probes=32)
    endpoints = [e for e in report.l3_endpoints if e.ip == "10.99.0.9"]
    assert endpoints and endpoints[0].probed is True
    assert not [g for g in topo.gaps if g.startswith("DISCOVERY_TRUNCATED")], topo.gaps
