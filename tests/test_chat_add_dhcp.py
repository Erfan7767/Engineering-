""""Add DHCP for the guests" plans a real pool from the design that was applied.

Before this, a DHCP request from the chat classified as UNKNOWN and was refused —
an honest refusal, but the platform already had everything needed to do it: the
zones, their subnets and their gateways, all allocated by the design engine and
all sitting in the chat's context after a run.

The property that carries the weight is where the numbers come from. The subnet
and gateway are read out of ``last_design`` — the zones that were actually
allocated and configured — never invented. A pool built on a guessed subnet
hands out addresses that are not on the wire: the client gets a lease, then
reaches nothing, which is a worse failure than the refusal this returns when no
design is known.

The plan is rendered by the same renderer and executed by the same executor a
full run uses, so a pool created from the chat and one created by the autopilot
cannot disagree about which addresses are handed out. That is asserted directly
rather than assumed.
"""
from __future__ import annotations

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.chat.device_runner import DeviceCommandRunner
from netops_autopilot.chat.operator import ChatOperator, IntentVerb, ReplyStatus
from netops_autopilot.chat.targeted_change import plan_add_dhcp, resolve_zone
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.core.failures import Failure
from netops_autopilot.specs_data import specs_data_dir

from .support.simfabric import SimFabricFactory, make_ledger_stack


@pytest.fixture
def rig():
    """A chat operator with a real design in context and a device it can write."""
    store, key_id, _counters, time_authority = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers(["BOND"])
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=time_authority).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=lambda r, h: fabric.open(r, h),
        port="SIM0", execute=True)

    allowlist = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    runner = DeviceCommandRunner(session_factory=lambda r: fabric.open(r, ()),
                                 allowlist=allowlist, store=store)
    op = ChatOperator(store=store, runner=None, device_runner=runner,
                      allowlist=allowlist)
    op.context.last_discovery = report.crawl
    op.context.last_topology = report.topology
    op.context.last_design = report.design
    return type("Rig", (), {"op": op, "fabric": fabric, "report": report,
                            "store": store})()


def _written(fabric) -> list[str]:
    return list(fabric.open("seed-01", ()).written_config)


# ------------------------------------------------------------------- planning
def test_planning_takes_the_subnet_from_the_design_and_sends_nothing(rig):
    before = _written(rig.fabric)
    reply = rig.op.handle("أضف DHCP للموظفين")
    assert reply.intent is IntentVerb.ADD_DHCP
    assert reply.status is ReplyStatus.OK, reply.detail

    zone = next(z for z in rig.report.design.zones if z.zone == "users")
    # The numbers in the reply are the zone's real ones, not a plausible pair.
    assert zone.subnet.split("/")[0] in reply.summary
    assert zone.gateway in reply.summary
    assert "ip dhcp pool users" in reply.detail
    assert f"network {zone.subnet.split('/')[0]}" in reply.detail
    # Planning sends nothing; the confirmation step would otherwise be theatre.
    assert _written(rig.fabric) == before
    assert rig.op.context.pending_change is not None


def test_the_chat_pool_matches_what_a_full_run_would_have_written(rig):
    """The two paths must not disagree about which addresses get handed out."""
    reply = rig.op.handle("add dhcp for voice")
    zone = next(z for z in rig.report.design.zones if z.zone == "voice")
    # The full run already configured this zone; its own rendered line is the
    # reference. Comparing against it is what stops the chat path drifting.
    reference = [c for c in _written(rig.fabric) if "pool voice" in c
                 or "network 10.240.0.128" in c]
    assert reference, "the full run did not configure the voice pool"
    for line in reference:
        assert line.strip() in reply.detail, (line, reply.detail)
    assert zone.gateway in reply.detail


def test_confirm_applies_it_for_real_and_reads_it_back(rig):
    rig.op.handle("add dhcp for users")
    reply = rig.op.handle("confirm")
    assert reply.status is ReplyStatus.OK, reply.detail
    assert "outcome: APPLIED" in reply.detail
    assert "verified on the device: True" in reply.detail
    # The device's own readback contains the pool, not just the plan's hope.
    assert any("ip dhcp pool users" in c for c in _written(rig.fabric))


# -------------------------------------------------------------------- refusals
def test_no_design_means_the_subnet_is_not_invented(rig):
    before = _written(rig.fabric)          # the full run already configured it
    rig.op.context.last_design = None
    reply = rig.op.handle("أضف DHCP للموظفين")
    assert reply.status is ReplyStatus.BLOCKED
    assert "لن أخترع" in reply.detail or "will not invent" in reply.detail
    assert _written(rig.fabric) == before


def test_an_unknown_zone_lists_the_real_ones(rig):
    reply = rig.op.handle("أضف DHCP للضيوف")
    assert reply.status is ReplyStatus.NEEDS_INPUT
    # This branch design has no guest zone; naming the zones that do exist is
    # the useful answer, and picking the nearest one would be a guess.
    assert "guest" not in reply.detail
    for name in ("users", "voice", "mgmt", "wan"):
        assert name in reply.detail


def test_an_ambiguous_zone_is_refused_not_picked(rig):
    before = _written(rig.fabric)
    reply = rig.op.handle("add dhcp for users and voice")
    assert reply.status is ReplyStatus.BLOCKED
    assert "users" in reply.detail and "voice" in reply.detail
    assert _written(rig.fabric) == before


# ------------------------------------------------------------- zone resolution
@pytest.mark.parametrize("text,zones,expected", [
    ("أضف DHCP للضيوف", ["guest", "users"], "guest"),
    ("أضف DHCP للموظفين", ["guest", "users"], "users"),
    ("add dhcp for guests", ["guest", "users"], "guest"),
    ("dhcp for the mgmt zone", ["mgmt", "users"], "mgmt"),
])
def test_resolve_zone_handles_arabic_affixes(text, zones, expected):
    """Arabic attaches the preposition and article to the noun, so "للضيوف" has
    to reach the vocabulary entry for "ضيوف". Looking the raw token up silently
    missed every prefixed form — the first version of this did exactly that."""
    got, matched = resolve_zone(text, zones)
    assert got == expected, (text, matched)


def test_resolve_zone_never_invents_a_zone():
    assert resolve_zone("أضف DHCP", ["users", "guest"]) == (None, ())
    assert resolve_zone("add dhcp for finance", ["users", "guest"]) == (None, ())


def test_resolve_zone_reports_ambiguity_instead_of_choosing():
    _got, matched = resolve_zone("dhcp for users and guest", ["users", "guest"])
    assert set(matched) == {"users", "guest"}


# ------------------------------------------------------------------- the plan
def test_plan_refuses_a_gateway_outside_the_subnet():
    with pytest.raises(Failure) as exc:
        plan_add_dhcp(change_id="c", request="r", device_ref="d",
                      vendor_os="ios-xe", zone="guest",
                      subnet="10.240.0.0/25", gateway="10.240.9.1")
    assert "GATEWAY_OUTSIDE_SUBNET" in exc.value.causes[0]


def test_plan_refuses_ipv6_rather_than_misapplying_the_ipv4_model():
    with pytest.raises(Failure) as exc:
        plan_add_dhcp(change_id="c", request="r", device_ref="d",
                      vendor_os="ios-xe", zone="guest",
                      subnet="2001:db8::/64", gateway="2001:db8::1")
    assert "SUBNET_NOT_IPV4" in exc.value.causes[0]


def test_plan_refuses_a_subnet_with_no_assignable_window():
    with pytest.raises(Failure) as exc:
        plan_add_dhcp(change_id="c", request="r", device_ref="d",
                      vendor_os="ios-xe", zone="guest",
                      subnet="10.240.0.0/31", gateway="10.240.0.0")
    assert "NO_DHCP_POOL" in exc.value.causes[0]


def test_plan_says_so_when_the_vendor_has_no_dhcp_template():
    """fortios genuinely has no dhcp template; that is a declared gap, and the
    refusal must name it rather than emit something plausible."""
    with pytest.raises(Failure) as exc:
        plan_add_dhcp(change_id="c", request="r", device_ref="d",
                      vendor_os="fortios", zone="guest",
                      subnet="10.240.0.0/25", gateway="10.240.0.1")
    assert "NOT_MODELED" in exc.value.causes[0]
    assert "fortios" in exc.value.causes[0]
