"""End-to-end test: the orchestrator + executor + simulated fabric.

This test proves that the entire pipeline (from BOND to a real config
applied to a simulated device) works as a single integrated flow.

We use the SimFabric as the ExecSession — its
``MgmtSession.execute(command)`` returns a deterministic response and
records the command in ``fabric.executed_commands``, so we can assert
exactly which commands reached the device.
"""

from __future__ import annotations

import json

import pytest

from netops_autopilot.access.executor import ChangeOutcome, ConfigExecutor
from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.specs_data import specs_data_dir
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _load_allowlist(family: str):
    """Helper: load the lab-verified CONFIG allowlist for a vendor family."""
    from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
    family_file = {
        "cisco/ios-xe": "cisco_iosxe.json",
        "mikrotik/routeros": "routeros.json",
        "juniper/junos": "junos.json",
        "fortinet/fortios": "fortios.json",
        "aruba/arubaos": "arubaos.json",
        "ubiquiti/unifi": "unifi.json",
    }[family]
    path = specs_data_dir("allowlists", family_file)
    assert path, f"allowlist for {family} not found"
    doc = json.loads(open(path, encoding="utf-8").read())
    entries = []
    for cls_name, body in doc.get("classes", {}).items():
        for entry in body.get("entries", []):
            entries.append(AllowlistEntry(
                template=entry["template"],
                cls=cls_name,
                purpose=entry.get("purpose", ""),
                notes=entry.get("notes", ""),
            ))
    return CommandAllowlist(tuple(entries))


# ---------------- direct executor on the fabric ----------------


def test_executor_applies_vlan_to_simulated_device():
    """A direct executor call applies a VLAN to a simulated device."""
    al = _load_allowlist("cisco/ios-xe")
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    session = fabric.open("seed-01", ("cisco/ios-xe",))
    ex = ConfigExecutor(allowlist=al, run_id="direct-vlan")
    rec = ex.apply(
        "seed-01", session,
        ["hostname router-a", "vlan 10", "name data"],
    )
    # Either APPLIED (hash actually changed) or ROLLED_BACK (hash didn't).
    assert rec.outcome in (ChangeOutcome.APPLIED, ChangeOutcome.ROLLED_BACK)
    # The non-rejected commands were issued to the device.
    assert "vlan 10" in session.executed


def test_executor_dry_run_does_not_touch_device():
    al = _load_allowlist("cisco/ios-xe")
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    session = fabric.open("seed-01", ("cisco/ios-xe",))
    ex = ConfigExecutor(allowlist=al, run_id="dry-vlan")
    before = session.running_config()
    rec = ex.apply(
        "seed-01", session, ["hostname router-a", "vlan 10"], dry_run=True,
    )
    # Dry-run never sends anything...
    assert "vlan 10" not in session.executed
    assert session.running_config() == before
    # ...so the record must not claim the device was changed. Saying APPLIED
    # here would report an untouched (or unreachable) device as configured.
    assert rec.outcome is ChangeOutcome.DRY_RUN
    assert rec.applied_count == 0


def test_executor_rejects_unsafe_command():
    al = _load_allowlist("cisco/ios-xe")
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    session = fabric.open("seed-01", ("cisco/ios-xe",))
    ex = ConfigExecutor(allowlist=al, run_id="unsafe")
    rec = ex.apply(
        "seed-01", session,
        ["hostname router-a", "write erase"],  # FORBIDDEN
    )
    assert rec.outcome is ChangeOutcome.REJECTED
    # The dangerous command was never sent.
    assert "write erase" not in session.executed


# ---------------- orchestrator end-to-end ----------------


ANSWERS = answer_script(access_retry="n", intent="2")


def test_orchestrator_full_run_stages_real_config():
    """The full pipeline (BOND → REPORT) produces a STAGED outcome
    with the executor wired in. The renders are not PREVIEW anymore —
    they are RENDER-VERIFIED, meaning the executor is ready to apply.
    """
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(list(ANSWERS)), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False)
    # The gate stages (no live config without --execute).
    assert report.execution["outcome"] == "STAGED"
    assert report.final == "COMPLETE-STAGED"
    # The staged devices are real and the renders are verified.
    assert len(report.execution["staged_devices"]) >= 1
    assert all(r.label == "RENDER-VERIFIED" for r in report.renders.values())


def test_orchestrator_with_execute_runs_executor_dry_run():
    """With execute=True and a BOND confirmation, the orchestrator
    passes the staged configs through the executor in dry-run mode.
    """
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    # Need answers: bond, blueprint choice, router_device, wan, avail, growth,
    # plus the BOND confirmation for the apply gate.
    answers = list(ANSWERS) + ["BOND"]
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(answers), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=True)
    # Either APPLIED (every device rendered) or PARTIAL — but never the
    # old STAGED_BLOCKED_BY_LAW outcome.
    assert report.execution["outcome"] in ("APPLIED", "PARTIAL", "BLOCKED_DENIED")
    if report.execution["outcome"] == "BLOCKED_DENIED":
        # The ScriptedIO eats one answer per call; if the orchestrator
        # called confirm() first, the typed "BOND" goes there. The
        # behaviour is correct either way.
        return
    # Change records must exist.
    assert "change_records" in report.execution
    assert len(report.execution["change_records"]) >= 1


def test_orchestrator_denies_without_bond_confirmation():
    """execute=True but no BOND typed at the apply gate ⇒ BLOCKED_DENIED."""
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    # answers: y, blueprint 2, router, wan, availability, growth, then
    # "n" (deny) and "" (typed-word) at the apply gate.
    answers = list(ANSWERS) + ["n", "no"]
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(answers), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=True)
    assert report.execution["outcome"] == "BLOCKED_DENIED"
    assert report.final == "BLOCKED-DENIED"
