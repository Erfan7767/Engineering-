"""A hostname is not an identity — two devices called the same thing are two.

Discovery keyed devices on the hostname a neighbour advertised
(`_norm_name(entry["neighbor_id"])`). Hostnames are not unique: two switches
both left at their default, two sites reusing a naming scheme, or a copy-paste
during provisioning all produce a collision, and the chance grows with the size
of the network. When it happened:

  - the second device was never crawled. The frontier check
    `if neighbor in visited: continue` skipped it, and `SessionFactory.open()`
    was never called for it — it could not have been configured even in
    principle.
  - both links were attributed to one device, so the map asserted something
    physically impossible: one device cabled to two different ports of the seed
    on the *same* remote port.
  - only the first device's management address survived, so the second was
    unreachable by construction as well as by omission.

The evidence that separates them is the advertised chassis id — but only at
first hand. Two entries in ONE reporting device's table, same hostname,
different chassis ids, on two of that device's own ports, are two devices; the
observer is looking at both. Two DIFFERENT reporters disagreeing about a third
device's chassis id proves nothing at all: LLDP carries a MAC address, CDP a
different form, and the same box is routinely described both ways. That case is
recorded as `IDENTITY_CONFLICT` and the devices are not split on it.

Resolution is memoised per (observer, name, chassis) because `_record_links`
reads a table while the crawl is still walking and `_link_report` reads every
table again at the end; without memoisation the same row of evidence named
different devices depending on when it was read.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.access.collector import Collector, SessionLockManager
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

FIXTURES = simfabric_fixtures_dir() / "cisco_iosxe"
READ_ONLY = (
    "show version", "show lldp neighbors detail", "show cdp neighbors detail",
)
ALLOWLIST = CommandAllowlist(tuple(
    AllowlistEntry(template=t, cls="READ_ONLY") for t in READ_ONLY))

ACCESS_VERSION = b"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software
cisco C9300-48P (ARM) processor
ACCESS-SW uptime is 1 day
System serial number           : FOC0000X000
Configuration register is 0x2102
"""


def _lldp_block(local_intf, chassis, remote_port, system_name, mgmt_ip):
    """One `show lldp neighbors detail` record. `chassis=None` omits the line,
    which is what CDP-style evidence looks like."""
    chassis_line = f"Chassis id: {chassis}\n" if chassis else ""
    mgmt_block = f"Management Addresses:\n    IP: {mgmt_ip}\n" if mgmt_ip else ""
    return (
        "------------------------------------------------\n"
        f"Local Intf: {local_intf}\n"
        f"{chassis_line}"
        f"Port id: {remote_port}\n"
        f"Port Description: {remote_port}\n"
        f"System Name: {system_name}\n"
        "System Description:\n"
        "Cisco IOS Software\n"
        "Time remaining: 100 seconds\n"
        f"{mgmt_block}\n"
    ).encode()


def _table(*blocks):
    return (b"Capability codes:\n    (R) Router, (B) Bridge\n\n" + b"".join(blocks)
            + f"\nTotal entries displayed: {len(blocks)}\n".encode())


#: One reporting device (the seed) sees two physically distinct switches that
#: both advertise the hostname ACCESS-SW, on two of its own ports.
COLLIDING = _table(
    _lldp_block("Gi1/0/3", "0011.2233.4455", "Gi0/1", "ACCESS-SW", "10.99.0.11"),
    _lldp_block("Gi1/0/4", "aabb.ccdd.eeff", "Gi0/1", "ACCESS-SW", "10.99.0.12"),
)

#: The very same two records, printed in the opposite order. Which device gets
#: the plain hostname must not depend on the order a switch happened to print
#: its neighbour table in.
COLLIDING_REVERSED = _table(
    _lldp_block("Gi1/0/4", "aabb.ccdd.eeff", "Gi0/1", "ACCESS-SW", "10.99.0.12"),
    _lldp_block("Gi1/0/3", "0011.2233.4455", "Gi0/1", "ACCESS-SW", "10.99.0.11"),
)

#: The same shape with no chassis id advertised at all: this could be two
#: devices, or one device with two uplinks. The evidence cannot say.
NO_CHASSIS = _table(
    _lldp_block("Gi1/0/3", None, "Gi0/1", "ACCESS-SW", "10.99.0.11"),
    _lldp_block("Gi1/0/4", None, "Gi0/2", "ACCESS-SW", None),
)


class ScriptedFactory:
    """Records every open() attempt: what separates 'never crawled' from
    'crawled and refused'."""

    def __init__(self, scripts):
        self._scripts = scripts
        self.opened: list[str] = []

    def open(self, device_ref, mgmt_hints):
        self.opened.append(device_ref)
        session = self._scripts.get(device_ref)
        if session is None:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"NO_ROUTE_KNOWN: {device_ref} has no session "
                                  f"script for hints {tuple(mgmt_hints)}",))
        return session


def _crawl(seed_table, scripts_extra=None):
    scripts = {
        "core-sw1": LoopbackSession({
            "show version": (FIXTURES / "show_version.txt").read_bytes(),
            "show lldp neighbors detail": seed_table,
            "show cdp neighbors detail": b"",
        }),
        "access-sw": LoopbackSession({
            "show version": ACCESS_VERSION,
            "show lldp neighbors detail": b"",
            "show cdp neighbors detail": b"",
        }),
    }
    scripts.update(scripts_extra or {})
    factory = ScriptedFactory(scripts)

    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    now = datetime(2026, 9, 13, 12, 0, 0, tzinfo=timezone.utc)
    counters = CounterCollector()
    twin = DigitalTwin(store, counters)
    engine = DiscoveryCrawlEngine(
        store=store, twin=twin,
        collector=Collector(
            store=store, key_id=key, allowlist=ALLOWLIST,
            time_authority=TimeAuthority(clock=lambda: now),
            locks=SessionLockManager(),
            default_budget=CommandBudget(max_retries=0)),
        parsers=default_registry(),
        link_engine=LinkEvidenceEngine(
            lambda: build_link_fsm(recorder=store, counters=counters)),
        claim_factory=ClaimFactory(store, default_registry()))
    report = engine.crawl(
        seed_ref="core-sw1", seed_family="cisco/ios-xe", session_factory=factory,
        allowlist_of=lambda family: ALLOWLIST)
    return report, TopologyMapEngine(twin).build(report), factory, engine


# ============================================== 1. first-hand evidence splits
def test_two_devices_sharing_a_hostname_are_two_devices():
    """Both are real, both are cabled, and neither may be dropped."""
    report, _topo, factory, _engine = _crawl(COLLIDING)
    refs = sorted(d.device_ref for d in report.devices)

    assert len(refs) == 3, refs
    assert "core-sw1" in refs
    access = [r for r in refs if r.startswith("access-sw")]
    assert len(access) == 2, refs
    # both were actually attempted — not one crawled and one imagined away
    assert sorted(factory.opened) == sorted(refs), factory.opened


def test_each_device_keeps_its_own_management_address():
    """Before the fix only the first address survived, so the second switch was
    unreachable by construction as well as by omission."""
    report, _topo, _factory, _engine = _crawl(COLLIDING)
    by_ref = {d.device_ref: d for d in report.devices}
    addresses = sorted(
        addr for ref, dev in by_ref.items() if ref.startswith("access-sw")
        for addr in dev.mgmt_addresses)
    assert addresses == ["10.99.0.11", "10.99.0.12"], addresses


def test_no_link_is_attributed_to_the_wrong_device():
    """The merged map claimed one device sat on two seed ports at the SAME
    remote port — physically impossible. Each link now ends where it belongs."""
    report, topo, _factory, _engine = _crawl(COLLIDING)
    # endpoint_a/endpoint_b are ordered by key, not by which side is the seed,
    # so each link is compared as an unordered pair.
    ends = sorted(
        tuple(sorted([(link.endpoint_a.device_ref, link.endpoint_a.interface),
                      (link.endpoint_b.device_ref, link.endpoint_b.interface)]))
        for link in report.links)
    assert ends == [
        (("access-sw", "Gi0/1"), ("core-sw1", "Gi1/0/3")),
        (("access-sw~aabbccddeeff", "Gi0/1"), ("core-sw1", "Gi1/0/4")),
    ], ends
    # the two links land on two different nodes
    assert len({e[0][0] for e in ends}) == 2
    assert len(topo.nodes) == 3


def test_the_collision_is_reported_not_silently_resolved():
    """Disambiguating is not enough; the operator is told the hostname lies."""
    report, topo, _factory, _engine = _crawl(COLLIDING)
    assert report.totals["identity_collisions"] == {
        "access-sw": ["001122334455", "aabbccddeeff"]}
    gap = [g for g in topo.gaps if g.startswith("IDENTITY_COLLISION")]
    assert gap, topo.gaps
    assert "2 distinct chassis ids" in gap[0], gap
    assert "001122334455" in gap[0] and "aabbccddeeff" in gap[0], gap
    assert "2 separate devices" in gap[0], gap


# ============================================ 2. second-hand evidence does not
def test_reporters_disagreeing_does_not_split_a_device():
    """Two neighbours describing the same box with different chassis ids is
    normal, not two devices. Splitting on it would invent equipment.

    Run against the simulated fabric, which carries exactly this case: core-sw2
    advertises the seed's chassis id as 0011.2233.4455 and access-sw1 advertises
    it as 6677.8899.aabb. Same physical seed, described two ways — which is what
    real LLDP/CDP does, since one carries a MAC address and the other a
    different form. The disagreement is reported; no second seed is invented.
    """
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y",
                                    intent="branch office with VoIP")),
        time_authority=time_auth)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric, port="SIM0", execute=False)

    refs = sorted(d.device_ref for d in report.crawl.devices)
    assert "seed-01" in refs, refs
    # the disagreement manufactured no second seed
    assert not [r for r in refs if r.startswith("seed-01~")], refs
    assert report.crawl.totals["identity_collisions"] == {}

    conflicts = report.crawl.totals["identity_conflicts"]
    assert "seed-01" in conflicts, conflicts
    assert set(conflicts["seed-01"]) == {"access-sw1", "core-sw2"}, conflicts
    ids = {c for cs in conflicts["seed-01"].values() for c in cs}
    assert len(ids) == 2, conflicts

    gap = [g for g in report.topology.gaps
           if g.startswith("IDENTITY_CONFLICT seed-01")]
    assert gap, report.topology.gaps
    assert "kept as one device" in gap[0], gap
    assert not [g for g in report.topology.gaps
                if g.startswith("IDENTITY_COLLISION")], report.topology.gaps


def test_a_hostname_with_no_chassis_id_is_never_split():
    """Absent evidence is not a second device. Two uplinks from one switch and
    two switches with no chassis id advertised are indistinguishable, so the
    honest answer is one device plus the links as seen."""
    report, topo, _factory, _engine = _crawl(NO_CHASSIS)
    refs = sorted(d.device_ref for d in report.devices)
    assert refs == ["access-sw", "core-sw1"], refs
    assert report.totals["identity_collisions"] == {}
    assert not [g for g in topo.gaps if g.startswith("IDENTITY_COLL")], topo.gaps
    # both physical links are still present, on the one device
    assert len(report.links) == 2
    seed_ports = sorted(
        end.interface for link in report.links
        for end in (link.endpoint_a, link.endpoint_b)
        if end.device_ref == "core-sw1")
    assert seed_ports == ["Gi1/0/3", "Gi1/0/4"], seed_ports


def test_which_device_gets_the_plain_name_does_not_depend_on_print_order():
    """The disambiguated ref has to be a property of the evidence.

    Both crawls see exactly the same two records; only the order the seed
    printed them in differs. If the plain hostname went to whichever record
    came first, the same physical network would get two different device
    inventories on two runs — and every ref-keyed record downstream (design
    roles, renders, ledger) would point somewhere else.
    """
    forward, _t1, _f1, _e1 = _crawl(COLLIDING)
    reversed_, _t2, _f2, _e2 = _crawl(COLLIDING_REVERSED)

    assert sorted(d.device_ref for d in forward.devices) == \
        sorted(d.device_ref for d in reversed_.devices)

    def shape(report):
        return sorted(
            tuple(sorted([(l.endpoint_a.device_ref, l.endpoint_a.interface),
                          (l.endpoint_b.device_ref, l.endpoint_b.interface)]))
            for l in report.links)
    assert shape(forward) == shape(reversed_), (shape(forward), shape(reversed_))

    # and the plain name went to the same chassis id both times
    by_ref = {d.device_ref: d.mgmt_addresses for d in forward.devices}
    by_ref_rev = {d.device_ref: d.mgmt_addresses for d in reversed_.devices}
    assert by_ref == by_ref_rev, (by_ref, by_ref_rev)
    assert by_ref["access-sw"] == ("10.99.0.11",), by_ref


# ================================================= 3. resolution is stable
def test_the_same_evidence_always_names_the_same_device():
    """`_record_links` reads a table mid-walk and `_link_report` reads them all
    again at the end. Without memoisation the first chassis id looked like a
    split on the second reading, and the links pointed at a device the crawl
    had never carried."""
    _report, _topo, _factory, engine = _crawl(COLLIDING)
    row = {"neighbor_id": "ACCESS-SW", "chassis_id": "0011.2233.4455",
           "local_intf": "Gi1/0/3", "neighbor_intf": "Gi0/1", "protocol": "LLDP"}
    first = engine._resolve_neighbor("core-sw1", row)
    assert first == "access-sw"
    for _ in range(5):
        assert engine._resolve_neighbor("core-sw1", row) == first
    # and the link endpoints agree with the devices the crawl actually carried
    report_devs = {d.device_ref for d in _report.devices}
    for link in _report.links:
        for end in (link.endpoint_a, link.endpoint_b):
            if end.device_ref != "UNKNOWN":
                assert end.device_ref in report_devs, (end.device_ref, report_devs)


def test_a_repeated_chassis_id_from_another_observer_is_the_same_device():
    """Two neighbours seeing the SAME box with the SAME chassis id must not
    produce two refs — that is corroboration, not a second device."""
    seed_table = _table(
        _lldp_block("Gi1/0/3", "0011.2233.4455", "Gi0/1", "ACCESS-SW", "10.99.0.11"),
    )
    # the neighbour itself names the seed back with the same chassis id it is
    # known by elsewhere
    access = LoopbackSession({
        "show version": ACCESS_VERSION,
        "show lldp neighbors detail": _table(
            _lldp_block("Gi0/2", "0011.2233.4455", "Gi1/0/6", "ACCESS-SW", None)),
        "show cdp neighbors detail": b"",
    })
    report, _topo, factory, _engine = _crawl(
        seed_table, scripts_extra={"access-sw": access})
    refs = sorted(d.device_ref for d in report.devices)
    assert refs == ["access-sw", "core-sw1"], refs
    assert report.totals["identity_collisions"] == {}
    assert "access-sw" in factory.opened
