"""A routed zone with no member port is a zone that cannot forward.

``campus`` allocated five zones. Access ports were distributed only across
INTERNAL/GUEST/DMZ, so MGMT and WAN were given an SVI and nothing else. An SVI
on a VLAN with no member port is admin-up but protocol-down — the address is
configured and not one packet can leave the zone. Verification caught it
(``SVI Vlan50 (wan) is up/down, not up/up``, three connectivity tests failed),
so it was never a false success, but the design was still producing a network
with no path to the provider.

It stayed hidden on the sample device because that device's baseline already had
VLANs 10/20/30/40 populated. Only the fifth zone, whose VLAN was new, came up
empty. Two defects were involved:

* the design never reserved a port for a zone the weighted distribution does not
  serve; and
* ``LoopbackSession.vlan_table`` merged created VLANs and renames into
  ``show vlan brief`` but not the access membership the applied
  ``switchport access vlan`` lines produced — so even once the design assigned
  the port, the device's own readback did not show it.
"""
from __future__ import annotations

import io
import contextlib

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ConsoleIO, ScriptedIO
from netops_autopilot.chat.operator import ChatOperator
from netops_autopilot.engines.blueprints import BLUEPRINTS
from netops_autopilot.simfabric import SimFabricFactory, make_ledger_stack, seed_session


# ============================================ the device's own readback


def _apply(session, *commands: str) -> None:
    for cmd in commands:
        session.execute(cmd, timeout_s=5.0)


def test_a_vlan_the_platform_populated_shows_its_ports():
    session = seed_session()
    _apply(session,
           "vlan 50", "name provider", "exit",
           "interface gi1/0/11", "switchport mode access",
           "switchport access vlan 50", "exit")
    assert session.vlan_members()[50] == ["gi1/0/11"]


def test_an_svi_on_a_populated_vlan_reads_up_up():
    """The whole point: the zone can actually forward."""
    session = seed_session()
    _apply(session,
           "vlan 50", "name provider", "exit",
           "interface Vlan50", "ip address 203.0.113.2 255.255.255.248", "exit",
           "interface gi1/0/11", "switchport mode access",
           "switchport access vlan 50", "exit")
    row = [l for l in session.ip_interface_brief().splitlines()
           if l.startswith("Vlan50")]
    assert row, session.ip_interface_brief()
    assert row[0].split()[-2:] == ["up", "up"], row[0]


def test_an_svi_on_an_empty_vlan_still_reads_protocol_down():
    """The negative case, so the fix is not 'report up/up always'.

    This is what made the campus WAN invisible: a protocol-down SVI is the
    device telling the truth, and the double has to keep telling it.
    """
    session = seed_session()
    _apply(session,
           "vlan 50", "name provider", "exit",
           "interface Vlan50", "ip address 203.0.113.2 255.255.255.248", "exit")
    assert session.vlan_members().get(50) == []
    row = [l for l in session.ip_interface_brief().splitlines()
           if l.startswith("Vlan50")]
    assert row[0].split()[-2:] == ["up", "down"], row[0]


def test_moving_a_port_removes_it_from_the_vlan_it_was_in():
    session = seed_session()
    _apply(session,
           "vlan 50", "exit", "vlan 60", "exit",
           "interface gi1/0/11", "switchport access vlan 50", "exit",
           "interface gi1/0/11", "switchport access vlan 60", "exit")
    members = session.vlan_members()
    assert members.get(50) == []
    assert members.get(60) == ["gi1/0/11"]


def test_a_rename_survives_the_membership_merge():
    """Regression: the merge once reset every created VLAN to VLANnnnn."""
    session = seed_session()
    _apply(session, "vlan 11", "name STAFF", "exit",
           "interface gi1/0/11", "switchport access vlan 11", "exit")
    row = [l for l in session.vlan_table().splitlines() if l.startswith("11 ")]
    assert row and "STAFF" in row[0], session.vlan_table()
    assert session.vlan_members()[11] == ["gi1/0/11"]


def test_trunk_ports_do_not_appear_in_the_vlan_table():
    """A real ``show vlan brief`` lists access ports only."""
    session = seed_session()
    _apply(session,
           "vlan 50", "exit",
           "interface gi1/0/11", "switchport mode trunk",
           "switchport trunk allowed vlan 10,50", "exit")
    assert session.vlan_members().get(50) == []


def test_baseline_membership_is_preserved_for_ports_nobody_touched():
    session = seed_session()
    before = session.vlan_members()
    _apply(session, "vlan 50", "exit",
           "interface gi1/0/11", "switchport access vlan 50", "exit")
    after = session.vlan_members()
    for vid, ports in before.items():
        if vid == 50:
            continue
        assert after.get(vid) == ports, f"vlan {vid} lost {ports}"


# ============================================ the design reserves a port


def _design_for(intent: str):
    store, key_id, _collector, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=ConsoleIO(),
                             time_authority=time_auth)
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    operator = ChatOperator(store=store, runner=None)
    engine.io = ScriptedIO(list(
        operator._autopilot_answers(intent=intent, apply_bond=True)))
    with contextlib.redirect_stdout(io.StringIO()):
        report = engine.run(
            probe_port_session_factory=lambda p: fabric.probe(p),
            mgmt_session_factory=fabric, port="SIM0", execute=True)
    return report, fabric


@pytest.mark.parametrize("blueprint", BLUEPRINTS,
                         ids=[b.blueprint_id for b in BLUEPRINTS])
def test_every_routed_zone_gets_at_least_one_member_port(blueprint):
    report, _fabric = _design_for(blueprint.blueprint_id)
    served = {a.zone for a in report.design.access}
    starved = [z.zone for z in report.design.zones if z.zone not in served]
    assert starved == [], (
        f"{blueprint.blueprint_id}: zones with an SVI and no member port: {starved}")


@pytest.mark.parametrize("blueprint", BLUEPRINTS,
                         ids=[b.blueprint_id for b in BLUEPRINTS])
def test_the_device_reports_every_routed_zone_as_up_up(blueprint):
    """The symptom that started this: a protocol-down SVI in the readback."""
    report, fabric = _design_for(blueprint.blueprint_id)
    session = fabric.device_session("seed-01")
    brief = session.execute("show ip interface brief", timeout_s=5.0).decode()
    down = [line for line in brief.splitlines()
            if line.startswith("Vlan") and line.split()[-2:] == ["up", "down"]]
    assert down == [], f"{blueprint.blueprint_id}: {down}"


def test_the_wan_assignment_names_the_port_the_operator_must_cable():
    """The human's remaining job is physical, so say which socket."""
    report, _fabric = _design_for("campus")
    wan = [a for a in report.design.access if a.zone == "wan"]
    assert wan, "no port was reserved for the WAN zone"
    reason = wan[0].reason.lower()
    # Asserted separately: a reason that says "cable the handoff here" without
    # naming the socket is not an instruction anybody can act on.
    assert wan[0].port.lower() in reason, reason
    assert "cable" in reason, reason
    assert "protocol-down" in reason, reason
    assert "provider handoff" in reason, reason


# ============================================ end to end


@pytest.mark.parametrize("blueprint", BLUEPRINTS,
                         ids=[b.blueprint_id for b in BLUEPRINTS])
def test_no_blueprint_leaves_a_failed_verification_test(blueprint):
    """Campus used to fail three connectivity tests on its WAN SVI.

    Unrun tests are still expected and are asserted elsewhere: a WAN whose
    address comes from the provider cannot be isolation-tested here, and the
    design says so rather than pretending.
    """
    report, _fabric = _design_for(blueprint.blueprint_id)
    verification = report.verification or {}
    assert list(verification.get("failed") or ()) == [], (
        f"{blueprint.blueprint_id}: {verification.get('reasons')}")
