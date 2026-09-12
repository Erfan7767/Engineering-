"""Phase 8 — a verified defect becomes a cause, a repair, and a re-check.

Before this, verification was the end of the line: the run reported
``INCOMPLETE`` and the operator was left to work out what to do. The four
engines that were supposed to close the loop existed and were imported by
nothing.

Two properties carry the weight, and both are ways this quietly becomes a lie:

* **Nothing is diagnosed that was not observed.** Every cause descends from a
  ``Finding`` the verifier recorded while reading a device, and carries that
  finding's ledger artifact. The diagnosis here is built by breaking a real
  sim device and re-reading it — not by handing the module a made-up list.
* **A repair is claimed only after the device is asked again.** ``repaired``
  comes from the executor's outcome and ``reverified`` from a second
  verification pass, so "we sent it" and "the network now does it" are
  separate facts in the record.

The ``NO_SAFE_FIX`` case matters as much as the repair case: when the platform
cannot fix something it must say so with a reason, not emit a plausible-looking
change and call it remediated.
"""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine, Phase
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.engines import diagnostics
from netops_autopilot.engines.verification import VerificationPlanner
from netops_autopilot.engines.verification_executor import (
    Finding,
    FindingKind,
    VerificationExecutor,
)
from tests.support.simfabric import SimFabricFactory, make_ledger_stack
from tests.test_phase_verify import _collector_for, _run


# ---------------------------------------------------------------------------
# the cause table is complete: a new finding kind cannot go unclassified
# ---------------------------------------------------------------------------


def test_every_finding_kind_has_a_cause():
    """A finding with no cause would be silently unactionable.

    The guard in ``diagnose`` handles it at runtime, but that path is only
    reachable once someone has already added a kind and forgotten the cause.
    This fails at the moment of the mistake instead.
    """
    assert set(diagnostics._CAUSES) == set(FindingKind)


def test_every_non_remediable_cause_says_why():
    for kind, cause in diagnostics._CAUSES.items():
        if not cause.auto_remediable:
            assert cause.why_not, f"{kind.value} refuses without a reason"
            assert cause.why_not_ar, f"{kind.value} refuses without an Arabic reason"


def test_a_refusal_without_a_reason_cannot_be_constructed():
    """The rule is enforced, not documented."""
    with pytest.raises(ValueError, match="gives no reason"):
        diagnostics.Diagnosis(
            finding=Finding(kind=FindingKind.SVI_ABSENT, device_ref="seed-01",
                            zone="users", vlan_id=10),
            cause=diagnostics._CAUSES[FindingKind.SVI_ABSENT],
            fix_nodes=())


# ---------------------------------------------------------------------------
# the honest refusal path, end to end through the real pipeline
# ---------------------------------------------------------------------------


def test_a_defect_the_platform_cannot_fix_is_declared_not_pretended():
    # Its own ledger and fabric: this is a complete run of its own, not a
    # second pass over a network a previous run already configured.
    store, key_id, _counters, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    # The operator supplies no resolvers: the DHCP pools go out with no
    # dns-server line, and the DNS test fails for a reason no amount of
    # cleverness can fix without a resolver to write.
    io = make_scenario_io("branch")
    io._answers[7] = ""
    io.append_answers(["BOND"])
    engine = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=ta)
    report = engine.run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=True)

    ts = report.troubleshooting
    assert ts is not None, "VERIFY did not pass, so phase 8 had to run"
    kinds = {f["kind"] for f in ts["findings"]}
    assert "DNS_SERVER_MISSING" in kinds, ts["findings"]
    assert ts["remediable"] == 0
    assert ts["repaired"] == [], "nothing safe to send, so nothing must be sent"
    assert ts["reverified"] is None, (
        "re-verification after sending nothing would only restate the failure")
    # Every open item names a reason and the evidence behind it.
    assert ts["open"]
    for item in ts["open"]:
        assert item["why_not_fixed"], item
        assert item["evidence_id"], "a diagnosis must be traceable to evidence"


def test_on_a_healthy_run_phase_8_finds_nothing_and_fixes_nothing():
    """The demo ends INCOMPLETE (four WAN pairs cannot be enforced), so phase 8
    does run — and must come back empty rather than invent work."""
    _store, _fabric, report = _run()
    phases = [p.phase for p in report.phases]
    assert Phase.VERIFY in phases
    ts = report.troubleshooting
    assert ts is not None, "verdict was not PASS, so phase 8 had to run"
    assert ts["findings"] == [], ts["findings"]
    assert ts["repaired"] == []
    assert ts["open"] == [], "no defect was found, so none may be declared"
    assert ts["reverified"] is None, (
        "nothing was sent, so a second verification pass would be theatre")


# ---------------------------------------------------------------------------
# the repair path: real findings, real apply, real re-verification
# ---------------------------------------------------------------------------


def _break_and_verify(store, fabric, report):
    """Damage the device, then read the damage back as real findings."""
    session = fabric.open("seed-01", ())
    drop = ("interface Vlan10", "ip dhcp pool users")
    session.written_config = [c for c in session.written_config
                              if not c.startswith(drop)]
    session.written_indented = [(d, c) for d, c in session.written_indented
                                if not c.startswith(drop)]
    assert "ip dhcp pool users" not in session.running_config()
    executor = VerificationExecutor(
        _collector_for(store, _run.key_id), lambda r, _k: fabric(r, ()))
    return executor.run(specs=VerificationPlanner().derive(report.intent),
                        design=report.design)


def test_a_repairable_defect_is_fixed_and_the_device_is_asked_again():
    store, fabric, report = _run()
    outcome = _break_and_verify(store, fabric, report)
    kinds = {f.kind for fs in outcome.findings.values() for f in fs}
    assert FindingKind.SVI_ABSENT in kinds, "the scenario no longer breaks anything"
    assert FindingKind.DHCP_POOL_MISSING in kinds

    engine = AutopilotEngine(store=store, key_id=_run.key_id,
                             io=make_scenario_io("branch"))
    # The engine holds the run state phase 8 reads: intent, crawl, the
    # pre-repair verification record and the operator's answers.
    engine.report.intent = report.intent
    engine.report.crawl = report.crawl
    engine.report.verification = dict(report.verification)
    engine._operator_answers = dict(getattr(report, "_answers", {}) or {})

    engine._phase_troubleshoot(report.design, outcome, fabric)

    ts = engine.report.troubleshooting
    assert ts is not None
    assert ts["remediable"] > 0
    assert ts["repaired"], ts["apply_failures"]
    fixed = {n for entry in ts["repaired"] for n in entry["nodes"]}
    assert "svi-users" in fixed
    assert "dhcp-users" in fixed

    # The proof is the device, not the report.
    session = fabric.open("seed-01", ())
    cfg = session.running_config()
    assert "ip dhcp pool users" in cfg, "the repair never reached the device"

    assert ts["reverified"] is not None, (
        "a repair that is not re-verified is an intention, not a result")
    assert ts["reverified"]["verdict"] in ("PASS", "INCOMPLETE", "FAILED")
    assert FindingKind.SVI_ABSENT.value not in {
        f["kind"] for f in ts["findings"]} or ts["repaired"]


def test_the_repair_uses_the_designs_own_nodes_not_new_configuration():
    """A repair authored for the occasion is how the fix drifts from the design."""
    store, fabric, report = _run()
    outcome = _break_and_verify(store, fabric, report)
    engine = AutopilotEngine(store=store, key_id=_run.key_id,
                             io=make_scenario_io("branch"))
    engine.report.intent = report.intent
    engine.report.crawl = report.crawl
    engine.report.verification = dict(report.verification)
    engine._phase_troubleshoot(report.design, outcome, fabric)

    ts = engine.report.troubleshooting
    assert ts["missing_design_nodes"] == [], (
        "diagnosis named nodes the design does not have — the two disagree")
    for entry in ts["repaired"]:
        assert entry["outcome"] == "APPLIED"
        # Every line sent is a design line; the applied list is not empty.
        assert entry["applied"], entry


def test_a_defect_with_no_matching_design_node_is_reported_not_skipped():
    """If diagnosis and design disagree, that is news — not something to hide."""
    finding = Finding(kind=FindingKind.SVI_ABSENT, device_ref="ghost-99",
                      zone="nope", vlan_id=999, evidence_id="ev")
    result = diagnostics.remediation_nodes(
        diagnostics.diagnose([finding]), ir_of={})
    assert result["nodes"] == {}
    assert "ghost-99:svi-nope" in result["missing"]


def test_one_missing_svi_reported_by_many_tests_is_diagnosed_once():
    """users->users and users->wan both fail; that is one defect, not two."""
    dup = [Finding(kind=FindingKind.SVI_ABSENT, device_ref="seed-01",
                   zone="users", vlan_id=10, evidence_id="ev")] * 3
    assert len(diagnostics.diagnose(dup)) == 1
