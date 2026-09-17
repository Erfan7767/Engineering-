""""Isolate the guests from the staff" plans a real ACL from the chat.

Three properties do the work, and each is a way this could quietly become a lie:

* **What is already in force is read from the device.** A deny that exists is
  reported as a no-op instead of being sent again — and a rule that does not
  exist is not assumed to.
* **A pair the design declared unenforceable stays unenforceable.** A deny
  naming a provider-assigned subnet matches nothing, so it reads as protection
  while protecting nothing. The refusal carries the design's own reason.
* **The deny is never sent without its permit.** An extended ACL with no permit
  at the end denies everything it does not name, so emitting the deny alone
  would black-hole the zone it was meant to protect.
"""
from __future__ import annotations

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.chat.device_runner import DeviceCommandRunner
from netops_autopilot.chat.operator import ChatOperator, IntentVerb, ReplyStatus
from netops_autopilot.chat.targeted_change import (
    plan_isolate_zones,
    read_acl_denies,
    resolve_zone_pair,
)
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.core.failures import Failure
from netops_autopilot.specs_data import specs_data_dir

from .support.simfabric import SimFabricFactory, make_ledger_stack

ACL_SAMPLE = """ip access-list extended ACL_USERS_IN
     10 deny ip 10.240.0.0 0.0.0.127 10.240.0.192 0.0.0.15
     20 permit ip any any
ip access-list extended ACL_VOICE_IN
     10 deny ip 10.240.0.128 0.0.0.63 10.240.0.192 0.0.0.15
"""


@pytest.fixture
def rig():
    store, key_id, _counters, time_authority = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
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
    return type("Rig", (), {"op": op, "fabric": fabric, "report": report})()


def _written(fabric) -> list[str]:
    return list(fabric.open("seed-01", ()).written_config)


# ------------------------------------------------------- what is already true
def test_an_isolation_already_in_force_is_reported_not_resent(rig):
    """The full run already denied users -> mgmt, and that is a fact read off
    the device, not an assumption from the design."""
    before = _written(rig.fabric)
    reply = rig.op.handle("اعزل الموظفين عن الإدارة")
    assert reply.intent is IntentVerb.ISOLATE
    assert reply.status is ReplyStatus.BLOCKED
    assert "ALREADY_ISOLATED" in reply.detail
    assert "10.240.0.0" in reply.detail and "10.240.0.192" in reply.detail
    assert _written(rig.fabric) == before


def test_a_provider_addressed_zone_is_isolated_with_any_not_a_dead_rule(rig):
    """`wan` takes its address from the provider, so the subnet on record
    never reaches the wire. Naming it would produce a rule that reads as
    protection and protects nothing; ``any`` on that side is one that works.

    This pair used to be refused outright, which was honest but left the
    isolation unconfigured. It is enforceable, so it is now enforced.
    """
    reply = rig.op.handle("اعزل المستخدمين عن wan")
    assert reply.status is ReplyStatus.OK, reply.detail


def test_the_planned_rule_covers_the_unknown_side_with_any():
    """The exact lines the chat would send, checked for the wildcard form."""
    from netops_autopilot.chat.targeted_change import plan_isolate_zones

    plan = plan_isolate_zones(
        change_id="c1", request="isolate users from wan", device_ref="seed-01",
        vendor_os="ios-xe", src_zone="users", dst_zone="wan",
        src_subnet="10.240.0.0/25", dst_subnet="10.240.0.208/29", vlan_id=10,
        dst_provider_assigned=True)

    denies = [c.strip() for c in plan.commands if c.strip().startswith("deny ip")]
    assert denies == ["deny ip 10.240.0.0 0.0.0.127 0.0.0.0 255.255.255.255"], denies
    # the allocated provider subnet must not appear anywhere in the rule
    assert not any("10.240.0.208" in c for c in plan.commands), plan.commands
    # and the permit that keeps the zone alive is still there
    assert any(c.strip() == "permit ip any any" for c in plan.commands)


def test_a_pair_with_both_ends_known_is_still_written_exactly():
    """The substitution must not leak into ordinary pairs."""
    from netops_autopilot.chat.targeted_change import plan_isolate_zones

    plan = plan_isolate_zones(
        change_id="c1", request="isolate users from mgmt", device_ref="seed-01",
        vendor_os="ios-xe", src_zone="users", dst_zone="mgmt",
        src_subnet="10.240.0.0/25", dst_subnet="10.240.0.192/28", vlan_id=10)

    denies = [c.strip() for c in plan.commands if c.strip().startswith("deny ip")]
    assert denies == ["deny ip 10.240.0.0 0.0.0.127 10.240.0.192 0.0.0.15"], denies


def test_an_unresolved_pair_asks_instead_of_picking(rig):
    reply = rig.op.handle("اعزل الشبكة")
    assert reply.status is ReplyStatus.NEEDS_INPUT
    for name in ("users", "voice", "mgmt", "wan"):
        assert name in reply.detail


def test_a_zone_cannot_be_isolated_from_itself(rig):
    reply = rig.op.handle("اعزل users عن users")
    assert reply.status is ReplyStatus.NEEDS_INPUT
    assert "users" in reply.detail


def test_an_isolation_request_is_not_answered_by_a_wireless_report(rig):
    """"الواي فاي" is a longer pattern than the verb "اعزل", and the matcher
    ranks by pattern length — so this used to come back as an access-point
    count, which reads like an answer."""
    reply = rig.op.handle("اعزل المستخدمين عن الواي فاي")
    assert reply.intent is not IntentVerb.WIRELESS
    assert reply.status is ReplyStatus.BLOCKED
    assert reply.data["detected_write_verb"] == "اعزل"
    assert reply.data["fallback_read_only_intent"] == "wireless"


# --------------------------------------------------------------- the parser
def test_read_acl_denies_only_records_what_actually_parses():
    parsed = read_acl_denies(ACL_SAMPLE)
    assert parsed["ACL_USERS_IN"] == {("10.240.0.0", "10.240.0.192")}
    assert parsed["ACL_VOICE_IN"] == {("10.240.0.128", "10.240.0.192")}
    # A permit is not a deny, and must not be counted as isolation.
    assert ("any", "any") not in parsed["ACL_USERS_IN"]


def test_read_acl_denies_on_an_empty_device_is_empty_not_invented():
    assert read_acl_denies("") == {}
    assert read_acl_denies("Interface  Status\n---- ----") == {}


# ------------------------------------------------------------ pair direction
def test_the_source_zone_is_the_one_that_loses_access():
    zones = ["guest", "users"]
    assert resolve_zone_pair("اعزل شبكة الضيوف عن الموظفين", zones) == (
        ("guest", "users"), ("guest", "users"))
    assert resolve_zone_pair("isolate guest from users", zones) == (
        ("guest", "users"), ("guest", "users"))


def test_a_pair_with_no_separator_is_not_guessed_at():
    assert resolve_zone_pair("اعزل الشبكة", ["users", "guest"]) == ((None, None), ())


# ----------------------------------------------------------------- the plan
def _plan(**kw):
    base = dict(change_id="c", request="r", device_ref="seed-01",
                vendor_os="ios-xe", src_zone="guest", dst_zone="users",
                src_subnet="10.240.1.0/25", dst_subnet="10.240.0.0/25",
                vlan_id=50)
    base.update(kw)
    return plan_isolate_zones(**base)


def test_the_deny_is_never_sent_without_its_permit():
    """The black-hole guard: an extended ACL with no permit at the end denies
    everything it does not name."""
    plan = _plan()
    text = "\n".join(plan.commands)
    assert "deny ip 10.240.1.0 0.0.0.127 10.240.0.0 0.0.0.127" in text
    assert "permit ip any any" in text
    assert text.index("deny ip") < text.index("permit ip any any"), (
        "the permit must come after the deny, or the deny is unreachable")
    # and the ACL is actually bound to the interface
    assert "ip access-group ACL_GUEST_IN in" in text


def test_the_verify_step_reads_the_rule_back_not_just_the_name():
    plan = _plan()
    assert plan.verify_command == "show ip access-lists"
    # The name alone would pass on an ACL containing the wrong statement.
    assert "ACL_GUEST_IN" in plan.verify_expect
    assert "10.240.1.0" in plan.verify_expect
    assert "10.240.0.0" in plan.verify_expect


def test_a_second_identical_deny_is_refused_as_a_no_op():
    existing = {"ACL_GUEST_IN": {("10.240.1.0", "10.240.0.0")}}
    with pytest.raises(Failure) as exc:
        _plan(existing=existing)
    assert "ALREADY_ISOLATED" in exc.value.causes[0]


def test_a_zone_cannot_be_isolated_from_itself_at_the_plan_level():
    with pytest.raises(Failure) as exc:
        _plan(src_subnet="10.240.0.0/25", dst_subnet="10.240.0.0/25")
    assert "SAME_ZONE" in exc.value.causes[0]


def test_a_vendor_with_no_acl_template_says_so():
    with pytest.raises(Failure) as exc:
        _plan(vendor_os="junos")
    assert "NOT_MODELED" in exc.value.causes[0]
    assert "junos" in exc.value.causes[0]


def test_an_ipv6_pair_is_refused_rather_than_misfiltered():
    with pytest.raises(Failure) as exc:
        _plan(src_subnet="2001:db8::/64")
    assert "SUBNET_NOT_IPV4" in exc.value.causes[0]
