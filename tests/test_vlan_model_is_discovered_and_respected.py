"""The VLAN model the device already has is discovered — and then respected.

`specs/data/allowlists/cisco_iosxe.json` has always declared `show vlan brief`
as READ_ONLY with fields `vlan_id, name, status, ports`. Nothing parsed it. So
the design engine chose VLAN ids from a fixed counter — `DEFAULT_VLAN_START`
plus ten — without ever reading the VLANs already on the switch.

Measured on the simulated fabric before the fix: `branch office with VoIP`
assigned **VLAN 20 to the voice zone**, while the device's own table said
`20 guest active Gi1/0/6, Gi1/0/7`. Applying that renames a live segment: the
guest VLAN becomes the voice VLAN, every guest device moves, and nothing in the
report says a VLAN that already existed was repurposed. Meanwhile the device
already had `100 voice`, unused — the VLAN an engineer would have used.

Two things follow, and both are needed:

* Discovery collects the VLAN model, so the platform is not blind to it.
* Allocation reuses a VLAN the device already named for that zone (zero churn,
  the operator's naming survives) and otherwise takes the lowest pool id that
  is not already on a device. Never one in use under a different name.
"""

from __future__ import annotations

from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.engines.design_engine import (
    DEFAULT_VLAN_START,
    VLAN_POOL_STEP,
    discovered_vlans,
    pick_vlan_id,
)
from netops_autopilot.parsers.l2l3_inventory import CiscoIosXeShowVlanBriefParser
from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir
from tests.support.simfabric import SimFabricFactory, make_ledger_stack

FIXTURES = simfabric_fixtures_dir() / "cisco_iosxe"
RAW = (FIXTURES / "show_vlan_brief.txt").read_bytes()


def _parsed():
    out = {}
    for obs in CiscoIosXeShowVlanBriefParser().parse(RAW, "raw-vlan"):
        out[obs.field] = obs
    return out


def _run(intent):
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y", intent=intent)),
        time_authority=time_auth)
    return engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                      mgmt_session_factory=fabric, port="SIM0", execute=False)


# ==================================================== 1. the parser itself
def test_the_vlan_model_is_parsed_from_real_output():
    obs = _parsed()
    assert obs["vlan_table"].parse_status.value == "OK"
    assert obs["vlan_count"].value == 10
    by_id = {r["vlan_id"]: r for r in obs["vlan_table"].value}
    assert by_id["20"] == {"vlan_id": "20", "name": "guest", "status": "active",
                           "ports": "Gi1/0/6, Gi1/0/7"}
    assert by_id["100"]["name"] == "voice"
    # A VLAN with no members is explicit absence, never ''
    assert by_id["100"]["ports"] is None
    assert by_id["1002"]["status"] == "act/unsup"


def test_prose_in_the_vlan_columns_is_never_a_row():
    """The fixture ends with a sentence in the same columns as a real row."""
    obs = _parsed()
    names = {r["name"] for r in obs["vlan_table"].value}
    assert not any("prose" in (n or "") for n in names), names
    assert obs["vlan_count"].value == 10


def test_no_header_means_missing_never_an_empty_table():
    """L01: 'no VLANs' and 'I could not read this' are different facts."""
    obs = {o.field: o for o in CiscoIosXeShowVlanBriefParser().parse(
        b"garbage that is not a vlan table\n", "raw")}
    assert obs["vlan_table"].parse_status.value == "MISSING"
    assert obs["vlan_count"].parse_status.value == "MISSING"


# ================================================ 2. discovery collects it
def test_the_crawl_collects_the_vlan_model():
    report = _run("branch office with VoIP").crawl
    seed = next(d for d in report.devices if d.device_ref == "seed-01")
    assert "show vlan brief" in [c.command for c in seed.commands]
    by_id = {r["vlan_id"]: r["name"] for r in seed.vlan_table}
    assert by_id["20"] == "guest", by_id
    assert by_id["100"] == "voice", by_id


# ================================================ 3. and the design respects it
def test_a_zone_reuses_the_vlan_the_device_already_named_for_it():
    """The device already had `100 voice`; that is the VLAN to use."""
    report = _run("branch office with VoIP")
    vlans = {z.zone: z.vlan_id for z in report.design.zones}
    assert vlans["voice"] == 100, vlans
    assert vlans["users"] == 10 and vlans["mgmt"] == 30 and vlans["wan"] == 40, vlans


def test_no_zone_is_put_on_a_vlan_the_device_uses_under_another_name():
    """The defect itself: VLAN 20 is `guest` on the switch and has members.

    Handing it to the voice zone renames a live segment.
    """
    report = _run("branch office with VoIP")
    by_id = {z.vlan_id: z.zone for z in report.design.zones}
    assert 20 not in by_id, by_id
    seed = next(d for d in report.crawl.devices if d.device_ref == "seed-01")
    guest = next(r for r in seed.vlan_table if r["vlan_id"] == "20")
    assert guest["name"] == "guest" and guest["ports"], guest
    reason = next(z.reason for z in report.design.zones if z.zone == "voice")
    assert "reuses the VLAN the device already has" in reason, reason


def test_with_no_vlan_evidence_the_old_allocation_still_holds():
    """Absent evidence must not change the answer — only real VLANs may."""
    assert pick_vlan_id({}, set(), "users") == DEFAULT_VLAN_START
    taken = set()
    got = []
    for zone in ("users", "guest", "mgmt", "wan"):
        vid = pick_vlan_id({}, taken, zone)
        taken.add(vid)
        got.append(vid)
    assert got == [10, 20, 30, 40], got


def test_a_free_id_skips_every_vlan_the_device_already_has():
    existing = {1: {"default"}, 10: {"users"}, 20: {"guest"}, 30: {"mgmt"},
                40: {"wan"}, 100: {"voice"}, 1002: {"fddi-default"}}
    assert pick_vlan_id(existing, set(), "servers") == 50
    # ...and skips ids this design has already handed out
    assert pick_vlan_id(existing, {50}, "servers") == 60


def test_a_vlan_two_devices_name_differently_is_never_reused():
    """Conflicting evidence about a VLAN's name is not a licence to pick one."""
    existing = {20: {"guest", "voice"}}
    assert pick_vlan_id(existing, set(), "voice") == DEFAULT_VLAN_START


def test_discovered_vlans_reads_only_reachable_devices():
    """An unreachable device's stale table must not constrain the design."""

    class _Dev:
        def __init__(self, ref, table):
            self.device_ref = ref
            self.vlan_table = table

    class _Report:
        devices = [_Dev("seed-01", ({"vlan_id": "20", "name": "guest"},)),
                   _Dev("gone-01", ({"vlan_id": "999", "name": "phantom"},))]

    assert discovered_vlans(_Report(), {"seed-01"}) == {20: {"guest"}}


def test_a_row_without_a_usable_id_is_skipped_not_guessed():
    class _Dev:
        device_ref = "seed-01"
        vlan_table = ({"vlan_id": "not-a-number", "name": "x"},
                      {"vlan_id": None, "name": "y"},
                      {"vlan_id": "30", "name": "mgmt"})

    class _Report:
        devices = [_Dev()]

    assert discovered_vlans(_Report(), {"seed-01"}) == {30: {"mgmt"}}


def test_the_pool_step_is_the_documented_one():
    assert VLAN_POOL_STEP == 10
    assert pick_vlan_id({}, set(), "z") == DEFAULT_VLAN_START
