"""A targeted change from the chat really reaches the device — and really doesn't until confirmed.

The chat could only change a network by re-running the whole autopilot. "Create
a VLAN for staff" had no path and was refused. It now plans against the
device's real VLAN table, shows the exact lines, and applies them on
confirmation through the same :class:`ConfigExecutor` the orchestrator uses.

Three properties carry the weight here, and each is a way this could quietly
become a lie:

* **Planning sends nothing.** A plan the operator has not approved must not
  touch the wire, or the confirmation step is theatre.
* **A collision is refused before anything is sent.** VLAN 30 on the sim is
  already ``mgmt``; creating over it is accepted by the CLI and discovered by
  an outage.
* **"Applied" and "verified" are separate facts.** A command the CLI accepted
  is not a line present in the running config, and only the second means the
  network changed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.chat.device_runner import DeviceCommandRunner
from netops_autopilot.chat.operator import (
    ChatOperator,
    IntentVerb,
    ReplyStatus,
)
from netops_autopilot.chat.targeted_change import (
    next_free_vlan,
    parse_vlan_request,
    read_existing_vlans,
)
from netops_autopilot.specs_data import specs_data_dir
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


class _Device:
    def __init__(self, ref: str, family: str = "cisco/ios-xe"):
        self.device_ref = ref
        self.classification = "SEED"
        self.status = "COMPLETE"
        self.identity = SimpleNamespace(vendor_family=family)


@pytest.fixture
def rig():
    """A chat operator wired to a sim device the operator can read and write."""
    store, key_id, _counters, _ta = make_ledger_stack()
    fabric = SimFabricFactory()
    allowlist = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    # SimFabric.open takes mgmt_hints; the runner's factory takes only the
    # device ref, which is the shape cli_main gives it on real hardware.
    runner = DeviceCommandRunner(session_factory=lambda ref: fabric.open(ref, ()),
                                 allowlist=allowlist, store=store)
    op = ChatOperator(store=store, runner=None, device_runner=runner,
                      allowlist=allowlist)
    op.context.last_discovery = SimpleNamespace(devices=(_Device("seed-01"),))
    return SimpleNamespace(op=op, store=store, fabric=fabric,
                           key_id=key_id, allowlist=allowlist)


def _written(fabric) -> list[str]:
    """Every config line the device actually received."""
    return list(fabric.open("seed-01", ()).written_config)


# ---------------------------------------------------------------------------
# planning sends nothing
# ---------------------------------------------------------------------------


def test_planning_reads_the_device_and_sends_nothing(rig):
    reply = rig.op.handle("أنشئ VLAN للموظفين")
    assert reply.intent is IntentVerb.CREATE_VLAN
    assert reply.status is ReplyStatus.OK, reply.detail
    # The plan is shown, the device is untouched.
    assert _written(rig.fabric) == [], (
        "planning wrote to the device — the confirmation step is then theatre")
    assert "vlan 11" in reply.detail and "name STAFF" in reply.detail
    assert rig.op.context.pending_change is not None


def test_the_plan_states_the_device_state_it_was_built_from(rig):
    reply = rig.op.handle("create a vlan for guests")
    assert "10 VLAN(s) present" in reply.detail, reply.detail
    # 1, 10, 20, 30, 40, 100 and 1002-1005 are taken on this device, so the
    # first genuinely free id is 11 — a counter held in memory would reuse 10.
    assert "11 is free" in reply.detail, reply.detail


def test_confirm_without_a_plan_refuses(rig):
    reply = rig.op.handle("confirm")
    assert reply.intent is IntentVerb.CONFIRM_CHANGE
    assert reply.status is ReplyStatus.BLOCKED
    assert _written(rig.fabric) == []


# ---------------------------------------------------------------------------
# execution is real and verified on the device
# ---------------------------------------------------------------------------


def test_confirm_applies_and_is_verified_from_the_device(rig):
    rig.op.handle("create a vlan for staff")
    reply = rig.op.handle("confirm")
    assert reply.status is ReplyStatus.OK, reply.detail
    assert "verified on the device: True" in reply.detail, reply.detail
    assert "outcome: APPLIED" in reply.detail
    # The device's own readback is quoted, not the plan's expectation.
    assert "11   STAFF" in reply.detail, reply.detail


def test_the_vlan_is_really_there_on_a_later_read(rig):
    """Proof that does not depend on the reply text."""
    rig.op.handle("create a vlan for staff")
    rig.op.handle("confirm")
    table = read_existing_vlans(
        rig.fabric.open("seed-01", ()).execute("show vlan brief", 5).decode())
    assert table.get(11) == "STAFF", table


def test_the_change_is_recorded_in_the_ledger(rig):
    before = rig.store.event_count()
    rig.op.handle("create a vlan for staff")
    rig.op.handle("confirm")
    assert rig.store.event_count() > before, (
        "an applied change left no ledger record")
    assert rig.store.verify_chain().ok is True


def test_a_plan_is_consumed_so_a_second_confirm_cannot_replay_it(rig):
    rig.op.handle("create a vlan for staff")
    assert rig.op.handle("confirm").status is ReplyStatus.OK
    assert rig.op.context.pending_change is None
    again = rig.op.handle("confirm")
    assert again.status is ReplyStatus.BLOCKED
    assert again.summary in ("nothing pending", "لا يوجد تغيير معلّق")


# ---------------------------------------------------------------------------
# collisions are refused before anything is sent
# ---------------------------------------------------------------------------


def test_an_id_already_in_use_is_refused_before_anything_is_sent(rig):
    reply = rig.op.handle("create vlan 30 labs")
    assert reply.status is ReplyStatus.BLOCKED, reply.detail
    assert "VLAN_ID_IN_USE" in reply.detail
    assert "mgmt" in reply.detail
    assert _written(rig.fabric) == []


def test_a_name_already_in_use_is_refused(rig):
    reply = rig.op.handle("create vlan 77 users")
    assert reply.status is ReplyStatus.BLOCKED, reply.detail
    assert "VLAN_NAME_IN_USE" in reply.detail
    assert _written(rig.fabric) == []


def test_repeating_a_change_that_already_happened_is_refused_not_reapplied(rig):
    rig.op.handle("create a vlan for staff")
    rig.op.handle("confirm")
    reply = rig.op.handle("create a vlan for staff")
    assert reply.status is ReplyStatus.BLOCKED, reply.detail
    # No id was named, so a fresh one is allocated and the refusal comes from
    # the duplicate NAME rather than a duplicate id. Either way it must point
    # the operator at the VLAN they already have instead of making a second.
    assert "VLAN 11" in reply.detail and "STAFF" in reply.detail, reply.detail


def test_the_id_is_allocated_from_the_devices_real_table(rig):
    """10 is taken on the sim; a counter kept in memory would reuse it."""
    reply = rig.op.handle("create a vlan for staff")
    assert "VLAN 11" in reply.summary, reply.summary
    assert next_free_vlan([1, 10, 20, 30]) == 11


# ---------------------------------------------------------------------------
# a failure is never reported as success
# ---------------------------------------------------------------------------


def test_a_change_that_does_not_appear_in_the_readback_is_not_verified(rig):
    """The outcome enum and the readback are two different sources."""
    from netops_autopilot.chat import targeted_change as tc

    plan = tc.plan_create_vlan(
        change_id="CHG-T", request="t", device_ref="seed-01",
        vendor_os="ios-xe", vlan_id=200, name="PROBE",
        existing=read_existing_vlans(""))
    session = rig.fabric.open("seed-01", ())
    report = tc.execute_change(
        plan, session=session, allowlist=rig.allowlist, store=rig.store,
        # A readback that answers with the wrong device's table.
        read_back=lambda ref, cmd: "VLAN Name\n---- ----\n1    default\n",
        key_id=rig.key_id)
    assert report.outcome == "APPLIED"
    assert report.verified is False, (
        "the CLI accepted the lines, but the device does not show them — "
        "reporting success here is the false success this suite exists to catch")
    assert report.succeeded is False


# ---------------------------------------------------------------------------
# parsing and table reading are not fabricating anything
# ---------------------------------------------------------------------------


def test_read_existing_vlans_ignores_headers_rules_and_prose():
    text = (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------\n"
        "1    default                          active    Gi1/0/1\n"
        "10   users                            active    Gi1/0/4\n"
        "\n"
        "Primary VLAN  Type  SAID  MTU  Parent\n"
        "-------------------------------------\n"
        "1002 fddi-default                     act/unsup\n"
    )
    assert read_existing_vlans(text) == {
        1: "default", 10: "users", 1002: "fddi-default"}


def test_read_existing_vlans_on_empty_input_is_empty_not_invented():
    assert read_existing_vlans("") == {}


def test_reserved_vlan_ids_are_never_allocated():
    # 1 is the default VLAN; 1002-1005 are legacy FDDI/Token Ring on Cisco.
    assert next_free_vlan([]) == 10
    assert next_free_vlan(range(10, 1000)) == 1000
    # 1000 and 1001 are taken by the caller; 1002-1005 are reserved, so the
    # next id a real device will accept is 1006.
    assert next_free_vlan(range(10, 1002)) == 1006


@pytest.mark.parametrize("text,want", [
    ("أنشئ VLAN للموظفين", {"name": "STAFF"}),
    ("أنشئ vlan 30 للضيوف", {"vlan_id": 30, "name": "GUESTS"}),
    ("أنشئ شبكة للصوت", {"name": "VOICE"}),
    ("create a vlan for staff", {"name": "STAFF"}),
    ("add vlan 30 staff", {"vlan_id": 30, "name": "STAFF"}),
    ("create vlan 44 cameras", {"vlan_id": 44, "name": "CCTV"}),
])
def test_the_request_is_parsed_the_same_way_in_both_languages(text, want):
    assert parse_vlan_request(text) == want


def test_an_out_of_range_id_is_rejected_not_sent():
    assert parse_vlan_request("create vlan 9999 lab") == {
        "vlan_id_rejected": 9999, "name": "LAB"}
