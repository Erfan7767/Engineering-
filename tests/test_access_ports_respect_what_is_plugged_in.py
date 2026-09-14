"""Access ports are assigned from what is actually plugged in — not from a list.

`_access_ports` built its pool as "harvested ports minus uplinks minus
infrastructure" and then spread them over the zones by weight. It never looked
at the port's discovered state, so a port that `show interfaces status` reported
as **connected, in VLAN 30** counted as free.

Measured on the fabric before the fix, `guest office` produced:

    gi1/0/8  connected, VLAN 30 (mgmt)  ->  guest, VLAN 20
    gi1/0/7  connected, VLAN 20 (guest) ->  users, VLAN 10
    gi1/0/3  notconnect, VLAN 1         ->  users
    gi1/0/10 disabled, VLAN 1           ->  users

The management port was moved into the guest VLAN — on a real switch that drops
management access to the device being configured — and every one of those lines
carried the reason "unused harvested port", including the two that discovery
showed as connected with a device in them. A reason that contradicts the
evidence it was derived from is worse than no reason.

Now:

* a port already in one of the design's VLANs, with something connected, is kept
  exactly as it is — for every zone, MGMT and WAN included;
* a port connected in a VLAN this design does not claim is left alone and
  reported (`PORTS_LEFT_ALONE`), never silently reassigned;
* genuinely unused ports are distributed by weight, and the reason says what
  discovery actually showed;
* a routed zone left with no member port reserves a free one, and if the device
  has none the shortage is reported (`NO_MEMBER_PORT`) instead of being covered
  by taking a port something is plugged into — which is how the old code
  satisfied the member-port invariant.
"""

from __future__ import annotations

from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.engines.blueprints import BLUEPRINTS
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.design_engine import (
    DesignEngine,
    UplinkAssignment,
    ZoneAssignment,
)
from netops_autopilot.engines.discovery_crawl import (
    CrawlReport,
    DeviceClass,
    DeviceResult,
    DeviceStatus,
)
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _run(intent):
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y", intent=intent)),
        time_authority=time_auth)
    return engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                      mgmt_session_factory=fabric, port="SIM0", execute=False)


def _discovered_ports(report, ref="seed-01"):
    device = next(d for d in report.crawl.devices if d.device_ref == ref)
    return {r["port"].lower(): (r["status"], r["vlan"]) for r in device.interface_table}


# ======================================= 1. nothing plugged in gets moved
def test_a_connected_port_in_another_zone_vlan_is_not_reassigned():
    """gi1/0/8 is connected and in VLAN 30. No end-user zone may take it."""
    report = _run("guest office")
    ports = _discovered_ports(report)
    assert ports["gi1/0/8"] == ("connected", "30"), ports["gi1/0/8"]

    by_port = {a.port: a for a in report.design.access}
    assert by_port["gi1/0/8"].zone == "mgmt", by_port["gi1/0/8"]
    assert by_port["gi1/0/8"].vlan_id == 30
    for zone in ("users", "guest"):
        zone_ports = [a.port for a in report.design.access if a.zone == zone]
        assert "gi1/0/8" not in zone_ports, (zone, zone_ports)


def test_ports_already_in_their_zone_are_kept_as_configured():
    report = _run("guest office")
    by_port = {a.port: a for a in report.design.access}
    for port, zone, vlan in (("gi1/0/4", "users", 10), ("gi1/0/5", "users", 10),
                             ("gi1/0/6", "guest", 20), ("gi1/0/7", "guest", 20)):
        assert by_port[port].zone == zone, (port, by_port[port])
        assert by_port[port].vlan_id == vlan
        assert "already in VLAN" in by_port[port].reason, by_port[port].reason
        assert "nothing plugged in is moved" in by_port[port].reason


def test_no_reason_claims_something_discovery_contradicts():
    """The reason must agree with the evidence it was derived from.

    An occupied port may only be described as already in its VLAN — never as
    unused. A free port may never be described as already configured.
    """
    report = _run("guest office")
    ports = _discovered_ports(report)
    for assignment in report.design.access:
        status, vlan = ports.get(assignment.port, ("", ""))
        occupied = status == "connected" and vlan.isdigit() and vlan != "1"
        if occupied:
            assert "already in VLAN" in assignment.reason, (assignment.port, assignment.reason)
            assert "unused" not in assignment.reason, assignment.reason
            assert int(vlan) == assignment.vlan_id, (assignment.port, vlan, assignment)
        else:
            assert "already in VLAN" not in assignment.reason, (assignment.port, status)


# ======================================= 2. the invariant is still honoured
def test_every_routed_zone_gets_a_member_port_without_stealing_one():
    """campus has five routed zones and twelve ports, eight of them occupied.

    The old code satisfied the member-port rule by handing `servers` a port that
    was carrying a device in another VLAN. It must now come from a genuinely
    free port instead.
    """
    report = _run("campus")
    ports = _discovered_ports(report)
    members = {}
    for a in report.design.access:
        members.setdefault(a.zone, []).append(a.port)
    for zone in report.design.zones:
        assert members.get(zone.zone), (zone.zone, members)
    # and nothing that was connected in a foreign VLAN was taken
    for zone_name, zone_ports in members.items():
        claimed = next(z.vlan_id for z in report.design.zones if z.zone == zone_name)
        for port in zone_ports:
            status, vlan = ports[port]
            if status == "connected" and vlan.isdigit() and vlan != "1":
                assert int(vlan) == claimed, (port, vlan, zone_name, claimed)
    assert not [r for r in report.design.blocked_reasons
                if r.startswith("NO_MEMBER_PORT")], report.design.blocked_reasons


# ============================== 3. the two honest outcomes, as unit behaviour
def _access(interface_table, zones, uplink_ports=("gi1/0/1",)):
    device = DeviceResult(device_ref="sw-01", classification=DeviceClass.SEED,
                          status=DeviceStatus.COMPLETE,
                          interface_table=tuple(interface_table))
    report = CrawlReport(devices=(device,), links=(), frontier_exhausted=True,
                         totals={})
    engine = DesignEngine(CapabilityEngine.load_builtin())
    blueprint = next(b for b in BLUEPRINTS if b.blueprint_id == "small_office")
    uplinks = [UplinkAssignment(device_ref="sw-01", local_port=p, peer_ref="core",
                                peer_port="Gi0/1", link_state="PROBABLE", reason="r")
               for p in uplink_ports]
    reasons: list[str] = []
    out = engine._access_ports(report, {"sw-01": device}, {"sw-01": "cisco/ios-xe"},
                               uplinks, list(zones), blueprint, reasons)
    return out, reasons


def _zone(name, kind, vlan):
    return ZoneAssignment(zone=name, kind=kind, vlan_id=vlan, subnet="10.0.0.0/24",
                          gateway="10.0.0.1", routed_on="sw-01", reason="r")


def test_a_port_in_a_vlan_no_zone_claims_is_left_alone_and_reported():
    table = [{"port": "gi1/0/1", "status": "connected", "vlan": "trunk"},
             {"port": "gi1/0/4", "status": "connected", "vlan": "77"},
             {"port": "gi1/0/5", "status": "notconnect", "vlan": "1"}]
    zones = [_zone("users", "INTERNAL", 10), _zone("mgmt", "MGMT", 30),
             _zone("wan", "WAN", 40)]
    assignments, reasons = _access(table, zones)
    assert not [a for a in assignments if a.port == "gi1/0/4"], assignments
    note = [r for r in reasons if r.startswith("PORTS_LEFT_ALONE")]
    assert note, reasons
    assert "gi1/0/4" in note[0] and "VLAN 77" in note[0], note


def test_a_full_device_reports_the_shortage_instead_of_taking_a_live_port():
    """Every port is connected in a VLAN this design does not claim."""
    table = [{"port": "gi1/0/1", "status": "connected", "vlan": "trunk"},
             {"port": "gi1/0/4", "status": "connected", "vlan": "77"},
             {"port": "gi1/0/5", "status": "connected", "vlan": "78"}]
    zones = [_zone("users", "INTERNAL", 10), _zone("mgmt", "MGMT", 30),
             _zone("wan", "WAN", 40)]
    assignments, reasons = _access(table, zones)
    assert [a for a in assignments if a.zone == "users"] == [], assignments
    shortage = [r for r in reasons if r.startswith("NO_MEMBER_PORT")]
    assert shortage, reasons
    assert "users" in shortage[0], shortage
    # and no occupied port was taken to cover the gap
    for a in assignments:
        row = next(r for r in table if r["port"] == a.port)
        assert not (row["status"] == "connected"
                    and row["vlan"].isdigit() and row["vlan"] != "1"), a


def test_a_default_vlan_port_with_nothing_connected_is_genuinely_free():
    table = [{"port": "gi1/0/1", "status": "connected", "vlan": "trunk"},
             {"port": "gi1/0/4", "status": "notconnect", "vlan": "1"},
             {"port": "gi1/0/5", "status": "disabled", "vlan": "1"},
             {"port": "gi1/0/6", "status": "notconnect", "vlan": "1"}]
    zones = [_zone("users", "INTERNAL", 10), _zone("mgmt", "MGMT", 30),
             _zone("wan", "WAN", 40)]
    assignments, reasons = _access(table, zones)
    assigned = {a.port for a in assignments}
    assert {"gi1/0/4", "gi1/0/5", "gi1/0/6"} <= assigned, assigned
    assert not [r for r in reasons
                if r.startswith(("PORTS_LEFT_ALONE", "NO_MEMBER_PORT"))], reasons
