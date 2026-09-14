"""Phase 6's failure policy — a device that refuses its config is a decision point.

The executor already handled the box: it pre-builds a rollback plan, issues it,
re-reads the device, and reports whether it was confirmed clean. What it cannot
decide is what the RUN does next — keep configuring the remaining devices,
isolate this one, or stop. That is ``FailureOrchestrator``'s job, and it was
imported by nothing.

Two things are pinned here.

* **The decision is taken by the orchestrator, not by branching written next to
  the apply loop.** The test recomputes the same scenario through
  ``FailureOrchestrator`` directly and requires the recorded decision to match,
  so the wiring cannot drift into its own private policy.
* **The executor's outcome and the run-level decision stay separate fields.**
  One is what happened to the device, the other what the run did about it. A
  run that decided FULL_ROLLBACK on a device the executor reported
  ROLLBACK_FAILED is the case an operator must see, and merging the two into a
  single status word would hide exactly that.
"""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.engines.failure_orchestrator import (
    Decision,
    FailureOrchestrator,
)
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _run_with_apply_failure(device: str, command: str):
    """Run the pipeline with one config line dropped by the device.

    ``LoopbackSession.fail_times`` raises a transport failure for exactly one
    command, which is what a flapping console or a rejected line looks like
    from the executor's side. Nothing about the failure is simulated at the
    orchestrator level — the executor sees a real exception.
    """
    store, key_id, _counters, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    session = fabric.open(device, ())
    session.fail_times[command] = 1
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    engine = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=ta)
    report = engine.run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=True)
    return store, fabric, report, session


def _a_late_svi_command() -> str:
    """An SVI line the branch design actually renders.

    These tests used to hardcode ``interface Vlan20``. VLAN ids are chosen
    from the VLANs the devices already have, so a hardcoded id silently stops
    being rendered, the injected failure never fires, and the test measures a
    successful apply while asserting a rollback. Read the target from the
    render instead.
    """
    store, key_id, _counters, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=ta).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=False)
    commands = [c for block in report.renders["seed-01"].blocks
                for c in block.commands]
    svis = [c for c in commands if c.startswith("interface Vlan")]
    assert svis, commands
    return svis[-1]

# ---------------------------------------------------------------------------
# the decision is the orchestrator's, and it is recorded
# ---------------------------------------------------------------------------


def test_a_real_apply_failure_produces_a_recorded_decision():
    _store, _fabric, report, _session = _run_with_apply_failure("seed-01", "vlan 10")
    ex = report.execution
    assert ex is not None
    decisions = ex["failure_decisions"]
    assert len(decisions) == 1, decisions
    dec = decisions[0]
    assert dec["device_ref"] == "seed-01"
    # Both facts, kept apart.
    assert dec["executor_outcome"] == "ROLLED_BACK"
    assert dec["decision"] == Decision.ISOLATE.value
    assert dec["reasons"], "a decision without reasons is not auditable"
    assert dec["counts_and_causes"].startswith("1/1")


def test_the_recorded_decision_matches_the_orchestrator_called_directly():
    """The wiring must not grow its own private policy."""
    _store, _fabric, report, _session = _run_with_apply_failure("seed-01", "vlan 10")
    dec = report.execution["failure_decisions"][0]
    # seed-01 IS the seed, so the management path is affected; the executor
    # rolled back, leaving nothing applied.
    from netops_autopilot.core.failures import Failure, FailureClass
    from netops_autopilot.engines.failure_orchestrator import FailureScenario
    # A Failure with no causes is refused by the core contract (L03/T4), so
    # the recorded causes are the ones the run actually produced.
    scenario = FailureScenario(
        change_id="x",
        failure=Failure(cls=FailureClass.ROLLED_BACK,
                        causes=tuple(dec["reasons"])),
        applied_nodes=(), failed_node=None, remaining_nodes=(),
        attempts_used=1, attempt_budget=1, management_path_affected=True)
    expected = FailureOrchestrator().decide(scenario)
    assert dec["decision"] == expected.decision.value
    assert dec["decision"] == Decision.ISOLATE.value


def test_a_failed_device_makes_the_run_incomplete_not_clean():
    _store, _fabric, report, _session = _run_with_apply_failure("seed-01", "vlan 10")
    ex = report.execution
    assert "seed-01" in ex["halted_after"]
    assert ex["outcome"] != "COMPLETE"
    assert report.final.startswith("INCOMPLETE"), report.final
    # The other two devices did take their config; that fact is not lost.
    outcomes = {r["device_ref"]: r["outcome"] for r in ex["change_records"]}
    assert outcomes["seed-01"] == "ROLLED_BACK"
    assert outcomes["access-sw1"] == "APPLIED"


def test_the_device_is_left_rolled_back_not_half_configured():
    """The most dangerous outcome is a partial apply reported as a failure.

    Fails late enough that real configuration is already on the device, so
    the rollback has something to undo. Asserted on the executor's own record
    rather than on the device's final config: phase 8 runs afterwards and
    legitimately puts some of it back, so a late read would be measuring the
    repair and calling it the rollback.
    """
    _store, _fabric, report, _session = _run_with_apply_failure(
        "seed-01", _a_late_svi_command())
    record = next(r for r in report.execution["change_records"]
                  if r["device_ref"] == "seed-01")
    assert record["outcome"] == "ROLLED_BACK"
    # The rollback plan was actually issued to the device, not merely built —
    # the defect this module once had, where the plan was constructed and then
    # discarded while the record still claimed ROLLED_BACK.
    assert record["rollback_issued"] > 0, record["rollback_commands"]
    assert record["rollback_succeeded"] == record["rollback_issued"], (
        "a rollback that did not complete must not read as ROLLED_BACK")
    # And the device was re-read to confirm it: the hash is back to the start.
    assert record["rollback_hash"] == record["before_hash"], (
        "the readback does not match the pre-change state")


def test_a_non_seed_failure_is_not_blamed_on_the_management_path():
    """The management-path flag must come from a fact, not from a default."""
    _store, _fabric, report, _session = _run_with_apply_failure("core-sw2",
                                                                "switchport mode trunk")
    dec = report.execution["failure_decisions"][0]
    assert dec["device_ref"] == "core-sw2"
    assert dec["management_path_affected"] is False
    assert "MANAGEMENT_PATH_IMPACT" not in dec["reasons"]


def test_no_failure_means_no_decisions():
    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=ta).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=True)
    assert report.execution["failure_decisions"] == []
    assert report.execution["halted_after"] == []


# ---------------------------------------------------------------------------
# the decision is deterministic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("outcome,mgmt,expected", [
    ("ROLLED_BACK", True, Decision.ISOLATE),
    ("ROLLED_BACK", False, Decision.HALT),       # nothing applied to unwind
    ("REJECTED", False, Decision.HALT),
])
def test_the_policy_is_a_pure_function_of_the_scenario(outcome, mgmt, expected):
    from netops_autopilot.core.failures import Failure, FailureClass
    from netops_autopilot.engines.failure_orchestrator import FailureScenario
    cls = {"ROLLED_BACK": FailureClass.ROLLED_BACK,
           "REJECTED": FailureClass.BLOCKED}[outcome]
    scenario = FailureScenario(
        change_id="x", failure=Failure(cls=cls, causes=("C",)),
        applied_nodes=(), failed_node=None, remaining_nodes=(),
        attempts_used=1, attempt_budget=1, management_path_affected=mgmt)
    assert FailureOrchestrator().decide(scenario).decision is expected


def test_an_irreversible_applied_state_is_never_rolled_back_automatically():
    """The one decision that must never be taken by a machine alone."""
    from netops_autopilot.core.failures import Failure, FailureClass
    from netops_autopilot.engines.config_ir import (
        EntityRef, IRNode, Operation, Reversibility)
    from netops_autopilot.engines.failure_orchestrator import FailureScenario
    node = IRNode(node_id="danger", target=EntityRef("DEVICE", "seed-01"),
                  operation=Operation.CREATE, feature="vlan",
                  vendor_os="ios-xe", parameters={"vlan_id": 9, "name": "X"},
                  reversibility=Reversibility.IRREVERSIBLE)
    scenario = FailureScenario(
        change_id="x", failure=Failure(cls=FailureClass.BLOCKED, causes=("C",)),
        applied_nodes=(node,), failed_node=None, remaining_nodes=(),
        attempts_used=1, attempt_budget=1, management_path_affected=False)
    decision = FailureOrchestrator().decide(scenario)
    assert decision.decision is Decision.HALT
    assert any("IRREVERSIBLE_APPLIED" in r for r in decision.reasons)


# ---------------------------------------------------------------------------
# ROLLED_BACK and ROLLBACK_FAILED must be genuinely different outcomes
# ---------------------------------------------------------------------------


def test_a_rollback_that_does_not_restore_the_device_is_not_called_clean():
    """The distinction is the whole point of the field.

    A device left in an unknown state and reported as ROLLED_BACK is the most
    dangerous false success in the system: the record says safe, the box says
    otherwise. So the sim is made to drop one of the undo lines as well, and
    the outcome must say so.
    """
    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    session = fabric.open("seed-01", ())
    session.fail_times[_a_late_svi_command()] = 1   # the apply fails here
    session.fail_times["no vlan 10"] = 1         # and one undo line is dropped
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=ta).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=True)

    record = next(r for r in report.execution["change_records"]
                  if r["device_ref"] == "seed-01")
    assert record["outcome"] == "ROLLBACK_FAILED", (
        f"the undo of `vlan 10` failed, so the device is not confirmed clean; "
        f"got {record['outcome']}")
    assert record["rollback_succeeded"] < record["rollback_issued"]
    # And the run treats an unconfirmed device as needing a human, never as
    # something to carry on past.
    dec = report.execution["failure_decisions"][0]
    assert dec["decision"] == Decision.HALT.value
    assert any("MANUAL_REQUIRED" in r for r in dec["reasons"]), dec["reasons"]
