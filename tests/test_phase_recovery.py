"""A device that drops off mid-run is a recovery case, not a summary line.

These drive FSM-5 through the orchestrator's real apply path with a management
session that stops answering, and check the three things that are easy to get
wrong:

* every level claimed was actually attempted — the engine refuses to invent an
  attempt outcome, and these fail if it ever starts to;
* the levels that could NOT be attempted are named, each with the real
  capability-matrix status behind it, rather than silently skipped;
* nothing is reported as applied when nothing was sent.
"""
from __future__ import annotations

from netops_autopilot.access.executor import ChangeOutcome, ConfigExecutor
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.engines.capability import CapabilityEngine

from .support.simfabric import SimFabricFactory, make_ledger_stack


def _run(go_silent_at: int):
    """Branch scenario where core-sw2 goes silent from call ``go_silent_at``.

    The count is over management-session opens, so the device stays reachable
    through discovery and the crawl and disappears only when its configuration
    is due — the case this phase exists for.
    """
    store, key_id, _collector, time_authority = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    calls: dict[str, int] = {}

    def mgmt(ref, hints):
        calls[ref] = calls.get(ref, 0) + 1
        if ref == "core-sw2" and calls[ref] >= go_silent_at:
            raise ConnectionError("core-sw2 stopped answering")
        return fabric.open(ref, hints)

    io = make_scenario_io("branch")
    io.append_answers(["BOND"])
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=time_authority).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=mgmt, port="SIM0", execute=True)
    return report, store, fabric


def _outcome(report):
    recovery = (report.execution or {}).get("recovery") or ()
    assert len(recovery) == 1, recovery
    assert recovery[0]["device_ref"] == "core-sw2"
    return recovery[0]


# --------------------------------------------------------------------- ladder
def test_an_unreachable_device_drives_the_recovery_ladder_for_real():
    """Both levels this host can attempt are attempted, and both are recorded."""
    report, _store, _fabric = _run(3)
    outcome = _outcome(report)

    assert outcome["terminal_state"] == "LOST"
    assert outcome["reached_level"] == "L1"
    # L0 and L1 are the two levels whose mechanism is a management session this
    # host actually holds; each carries a real result, not an assumed one.
    assert [(a["level"], a["result"]) for a in outcome["attempts"]] == [
        (0, "FAILED"), (1, "FAILED")]
    assert all("stopped answering" in a["detail"] for a in outcome["attempts"])


def test_the_levels_it_could_not_attempt_are_named_not_skipped():
    """Skipping a rung silently is how a device gets quietly written off."""
    report, _store, _fabric = _run(3)
    skipped = _outcome(report)["paths_not_attempted"]

    assert set(skipped) == {"L2_config_rollback", "L3_oob", "L4_console_recovery"}
    # L2 is impossible for a structural reason: it needs the session we lack.
    assert "management session" in skipped["L2_config_rollback"]

    # L3/L4 carry the real matrix status for this platform, read at run time
    # rather than a status written into the message by hand.
    capability = CapabilityEngine.load_builtin()
    for field, mechanism in (("L3_oob", "oob"),
                             ("L4_console_recovery", "console_recovery")):
        status = capability.recovery_lookup("cisco/ios-xe", mechanism).status.value
        assert status in skipped[field], (field, status, skipped[field])


def test_recovery_leaves_real_rows_in_the_ledger():
    """A fabricated evidence id would pass the guard and corrupt the audit trail."""
    report, store, _fabric = _run(3)
    transitions = [t for t in store.transitions() if t.entity_ref == "core-sw2"]
    assert transitions, "recovery recorded nothing"

    guards = {t.guard_id for t in transitions}
    assert "MGMT_SESSION" in guards            # the classified failure
    assert "RECOVERY_EXHAUSTED" in guards      # the honest exit
    # The FSM wrote its own rows as it walked the ladder, so the path is
    # auditable from the ledger alone: 5.1 entered L0, 5.2 stepped L0 -> L1
    # on a real failed attempt, 5.6 ended in LOST.
    assert {"5.1", "5.2", "5.6"} <= guards, guards
    # Every row points at evidence; an empty list is not allowed by the model.
    assert all(t.evidence_ids for t in transitions)


# ----------------------------------------------------------------- recovered
def test_a_device_that_answers_on_retry_is_recovered_and_configured():
    """Recovery is not only about giving up: a retry that works must apply."""
    store, key_id, _collector, time_authority = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    calls: dict[str, int] = {}

    def mgmt(ref, hints):
        calls[ref] = calls.get(ref, 0) + 1
        # Gone for exactly one open: L0 fails, L1 gets through.
        if ref == "core-sw2" and calls[ref] == 3:
            raise ConnectionError("transient")
        return fabric.open(ref, hints)

    io = make_scenario_io("branch")
    io.append_answers(["BOND"])
    report = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=time_authority).run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=mgmt, port="SIM0", execute=True)

    outcome = _outcome(report)
    assert outcome["terminal_state"] == "RECOVERED"
    # The very first retry got through, so the ladder never left L0 — and the
    # record says so rather than claiming more escalation than happened.
    assert outcome["reached_level"] == "L0"
    assert [(a["level"], a["result"]) for a in outcome["attempts"]] == [(0, "OK")]

    # It recovered AND then took its configuration for real.
    by_ref = {r["device_ref"]: r for r in report.execution["change_records"]}
    assert by_ref["core-sw2"]["outcome"] == "APPLIED"
    assert by_ref["core-sw2"]["applied_count"] > 0
    assert report.execution.get("halted_after") == []


# ----------------------------------------------------------- nothing applied
def test_an_unreachable_device_is_never_counted_as_applied():
    """The regression this phase was written for."""
    report, _store, _fabric = _run(3)
    dead = {r["device_ref"]: r
            for r in report.execution["change_records"]}["core-sw2"]

    assert dead["outcome"] == "DRY_RUN"
    assert dead["applied_count"] == 0
    assert dead["rollback_issued"] == 0
    assert any(c.startswith("DEVICE_UNREACHABLE") for c in dead["failure_causes"])
    # The run as a whole does not claim a success it did not achieve.
    assert report.final.endswith("PARTIAL")


def test_the_summary_counts_only_devices_that_really_took_the_config():
    """The [EXECUTION_GATE] tally is what an operator reads as 'it worked'."""
    report, _store, _fabric = _run(3)
    records = report.execution["change_records"]
    # Two devices were rendered; only one is reachable.
    assert len(records) == 2
    assert [r["device_ref"] for r in records if r["outcome"] == "APPLIED"] == ["seed-01"]
    # The unreachable device is present, so it is not silently dropped.
    assert "core-sw2" in {r["device_ref"] for r in records}


def test_a_dry_run_can_never_report_applied():
    """Invariant, independent of the orchestrator."""
    from .test_executor import _build_allowlist, _FakeSession

    ex = ConfigExecutor(allowlist=_build_allowlist(), run_id="dry")
    rec = ex.apply("dev1", _FakeSession(), ["hostname router-a", "vlan 10"],
                   dry_run=True)
    assert rec.outcome is ChangeOutcome.DRY_RUN
    assert rec.applied_count == 0
    assert rec.command_count == 2          # the plan is still fully visible
    assert rec.rejected_count == 0         # and it did clear the gate
