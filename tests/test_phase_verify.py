"""Phase 7 — the run asks the network whether it works, and cannot lie about it.

Before this phase existed the pipeline ended at ``EXECUTION_GATE`` → ``REPORT``.
The executor proved the configuration *landed* (no error strings, hash moved,
lines present in the readback) and the run reported ``COMPLETE-APPLIED`` —
having never once asked whether the network did what the operator asked for.
"Config stuck" is not "requirement met".

The first honest run of this phase found three real defects that the old
verdict had been hiding:

* the operator was asked for the resolvers to hand to clients, answered, and
  the answer was silently dropped on the way to the design engine — every DHCP
  pool went out with no ``dns-server`` line;
* the run had no default route, so a network whose intent required internet
  egress could not reach the internet;
* and the test double's ``show running-config`` lost the indentation a real
  device emits, so a parser written against real output matched nothing.

The invariants below are what keep the phase honest rather than decorative.
"""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine, Phase
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.engines.verification import VerificationPlanner
from netops_autopilot.engines.verification_executor import (
    CLIENT_ZONE_KINDS,
    VerificationExecutor,
)
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _run(execute: bool = True):
    store, key_id, _counters, ta = make_ledger_stack()
    _run.key_id = key_id
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    if execute:
        io.append_answers(["BOND"])
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=ta)
    report = engine.run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=execute)
    return store, fabric, report


# ======================================================== the phase runs
def test_verify_is_a_real_phase_in_the_pipeline():
    _store, _fabric, report = _run()
    phases = [p.phase for p in report.phases]
    assert Phase.VERIFY in phases, phases
    # it runs after the config was actually applied, not before
    assert phases.index(Phase.VERIFY) > phases.index(Phase.EXECUTION_GATE)


def test_verify_does_not_run_when_nothing_was_applied():
    """Staging is not applying; there is no post-apply state to check."""
    _store, _fabric, report = _run(execute=False)
    assert Phase.VERIFY not in [p.phase for p in report.phases]
    assert report.verification is None


def test_the_matrix_covers_every_zone_pair_and_every_service():
    _store, _fabric, report = _run()
    v = report.verification
    zones = {z.zone for z in report.design.zones}
    assert v["tests_total"] == len(zones) ** 2 + len(
        report.intent.required_services)


# ============================================ it cannot claim false success
def test_an_unrun_test_is_never_counted_as_passed():
    _store, _fabric, report = _run()
    v = report.verification
    assert v["graded"] + len(v["unrun"]) == v["tests_total"]
    assert not (set(v["passed"]) | set(v["failed"])) & set(v["unrun"])


def test_every_failure_names_the_precondition_that_was_missing():
    """A bare FAIL is not actionable and is indistinguishable from a bug."""
    _store, _fabric, report = _run()
    v = report.verification
    for tid in v["failed"]:
        assert v["reasons"].get(tid), f"{tid} failed with no reason"


def test_every_unrun_test_says_why_it_could_not_be_graded():
    _store, _fabric, report = _run()
    for _tid, why in report.verification["unrun"].items():
        assert why.strip()


def test_a_failed_verification_downgrades_the_verdict():
    """Applied but not working is not COMPLETE."""
    _store, _fabric, report = _run()
    v = report.verification
    if v["verdict"] != "PASS":
        assert not report.final.startswith("COMPLETE"), report.final
        assert report.final.startswith("INCOMPLETE-"), report.final


# ================================================== evidence is real, not asserted
def test_every_evidence_id_is_a_ledgered_artifact():
    """Each graded test cites an artifact that actually exists in the ledger."""
    store, _fabric, report = _run()
    v = report.verification
    assert v["evidence_count"] > 0
    known = {a.raw_id for a in store.raw_artifacts()}
    assert known, "no artifacts in the ledger — the check would be vacuous"
    missing = [i for i in v["evidence_ids"] if i not in known]
    assert not missing, missing


def test_verification_read_commands_the_devices_actually_answered():
    """The evidence came from read-only commands the allowlist permits."""
    _store, fabric, report = _run()
    session = fabric.open("seed-01", ())
    executed = {c.strip() for c in session.executed}
    assert "show ip interface brief" in executed
    assert "show running-config" in executed
    assert "show ip route" in executed


def test_dhcp_scope_is_reported_not_silently_narrowed():
    """MGMT is infrastructure and needs no pool — but the exclusion is visible."""
    _store, _fabric, report = _run()
    scope = report.verification["dhcp_scope"]
    assert scope, "an empty scope would make the DHCP test vacuous"
    kinds = {z.zone: z.kind for z in report.design.zones}
    assert all(kinds[z] in CLIENT_ZONE_KINDS for z in scope)
    assert all(z not in scope for z, k in kinds.items() if k not in CLIENT_ZONE_KINDS)


# ============================== the defect this phase found must stay fixed
def test_the_operators_dns_answer_reaches_the_devices():
    """Asked, answered, and applied — not silently discarded.

    `_phase_design` built its answers dict with `router_device` only, so the
    resolvers collected during INTENT_ELICITATION never reached the design
    engine and every pool went out with no `dns-server` line.
    """
    _store, fabric, report = _run()
    session = fabric.open("seed-01", ())
    dns_lines = [c for c in session.written_config if c.startswith("dns-server")]
    client_zones = [z for z in report.design.zones if z.kind in CLIENT_ZONE_KINDS]
    assert len(dns_lines) == len(client_zones), (
        f"{len(client_zones)} client zones but {len(dns_lines)} pools carry "
        f"resolvers: {dns_lines}")
    for line in dns_lines:
        assert "1.1.1.1" in line, line


def test_verification_grades_from_applied_state_not_from_the_design():
    """Wipe what was applied and re-run: the verdict must move with the device.

    If verification were reading the design instead of the device, removing the
    configuration would change nothing and the phase would be decoration.
    """
    store, fabric, report = _run()
    assert report.verification["verdict"] == "PASS", report.verification["failed"]

    session = fabric.open("seed-01", ())
    assert "ip dhcp pool" in session.running_config()
    # Remove the pools the executor actually wrote, then ask the same question
    # again against the same devices.
    session.written_config = [c for c in session.written_config
                              if not c.startswith("ip dhcp pool")]
    session.written_indented = [(d, c) for d, c in session.written_indented
                                if not c.startswith("ip dhcp pool")]
    assert "ip dhcp pool" not in session.running_config()

    specs = VerificationPlanner().derive(report.intent)
    executor = VerificationExecutor(
        _collector_for(store, _run.key_id), lambda ref, _kind: fabric(ref, ()))
    again = executor.run(specs=specs, design=report.design)
    dhcp = [r for r in again.results if "SERVICE_UP:dhcp" in r.test_id]
    assert dhcp, f"dhcp test not graded; unrun={again.unrun}"
    assert dhcp[0].outcome.value == "FAIL", (
        "removing the applied pools did not change the verdict — verification "
        "is reading the design, not the device")
    assert again.reasons.get(dhcp[0].test_id)


def _collector_for(store, key_id):
    from netops_autopilot.access.collector import Collector, SessionLockManager
    from netops_autopilot.access.collector import CommandBudget
    from netops_autopilot.access.allowlist import CommandAllowlist
    from netops_autopilot.core.timeauth import TimeAuthority
    from pathlib import Path
    from datetime import datetime, timezone
    allowlist = CommandAllowlist.load_vendor(
        Path("specs/data/allowlists"), "cisco/ios-xe")
    return Collector(store=store, key_id=key_id, allowlist=allowlist,
                     time_authority=TimeAuthority(
                         clock=lambda: datetime.now(timezone.utc)),
                     locks=SessionLockManager(),
                     default_budget=CommandBudget(max_retries=1))
