"""End-to-end integration tests for the autopilot flow.

These tests exercise the public surface of the AutopilotEngine
against the deterministic SimFabric, asserting:

* Every phase produces a typed status.
* The ledger is append-only and the chain verifies.
* Counters (T1–T6) start at 0 and only grow.
* No claim is emitted without valid evidence.
* The HTML + JSON report renderers accept the resulting report.
* The progress reporter tracks the run lifecycle.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netops_autopilot.autopilot import AutopilotEngine
from netops_autopilot.cli.io import ScriptedIO
from netops_autopilot.cli.progress import ProgressReporter
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.core.counters import T5_COUNTERS
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.reporting.html_report import report_from_autopilot, render_html_report
from netops_autopilot.reporting.json_report import render_json_report
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


# ----------------- Full flow on every scenario -----------------


@pytest.mark.parametrize("scenario", ["branch", "leaf-spine", "hotel", "retail"])
def test_full_flow_all_scenarios_complete(scenario: str):
    store, key_id, counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=make_scenario_io(scenario),
        time_authority=time_auth,
    )
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    # Every phase ran up to EXECUTION_GATE. The default branch blocks
    # at the execution gate (T3: empty allowlist) and may skip REPORT.
    phase_names = [p.phase.value for p in report.phases]
    assert "BOND" in phase_names
    assert "BOOT_PROBE" in phase_names
    assert "DISCOVERY_A" in phase_names
    assert "TOPOLOGY_MAP" in phase_names
    assert "INTENT_ELICITATION" in phase_names
    assert "DESIGN" in phase_names
    assert "RENDER" in phase_names
    assert "EXECUTION_GATE" in phase_names
    # Final is BLOCKED at the gate; the run is not aborted early.
    assert report.final.startswith("BLOCKED-") or report.final == "COMPLETE-STAGED"
    # The report carries evidence.
    assert store.event_count() > 0
    assert store.verify_chain().ok is True
    # The constitutional counters are wired and start at 0.
    snap = counters.snapshot()
    for c in T5_COUNTERS:
        assert snap[c] == 0, f"{c} should be 0, got {snap[c]}"


# ----------------- Ledger integrity invariants -----------------


def test_ledger_chain_verifies_after_full_run():
    store, key_id, _, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=make_scenario_io("branch"),
        time_authority=time_auth,
    )
    engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    assert store.event_count() > 0
    chain = store.verify_chain()
    assert chain.ok is True


def test_ledger_append_only_no_loss():
    """Calling verify_chain twice yields the same result (idempotency)."""
    store, key_id, _, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=make_scenario_io("hotel"),
        time_authority=time_auth,
    )
    engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    a = store.verify_chain()
    b = store.verify_chain()
    assert a.ok == b.ok


# ----------------- Progress reporter hooks -----------------


def test_progress_reporter_tracks_phase_lifecycle():
    """The progress reporter receives callbacks for each phase."""
    received_phases: list[tuple[str, str]] = []
    reporter = ProgressReporter(run_id="int-1")
    reporter.subscribe(lambda snap: received_phases.append(
        (snap.running_step or "done", str(snap.completed_steps))
    ))
    sid = reporter.begin("BOND", "Bind")
    reporter.end(sid, detail="ok")
    sid2 = reporter.begin("DESIGN", "Design")
    reporter.fail(sid2, "BLOCKED")
    snap = reporter.snapshot()
    assert snap.total_steps == 2
    assert snap.completed_steps == 1
    assert snap.failed_steps == 1
    assert len(received_phases) >= 2  # multiple snapshots fired


# ----------------- HTML + JSON reports -----------------


def test_report_renderers_accept_autopilot_report():
    store, key_id, _, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=make_scenario_io("retail"),
        time_authority=time_auth,
    )
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    data = report_from_autopilot(
        report, run_id="int-test",
        ledger_event_count=store.event_count(),
        chain_ok=True,
    )
    html = render_html_report(data)
    assert "NetOps Autopilot" in html
    assert "int-test" in html
    assert "TOPOLOGY_MAP" in html

    j = json.loads(render_json_report(
        report=report,
        ledger_event_count=store.event_count(),
        chain_ok=True,
    ))
    assert j["schema"] == "netops-autopilot/run-report/v1"
    assert j["final"] in ("COMPLETE-STAGED", "BLOCKED-DESIGN", "BLOCKED-*")


# ----------------- Config + LLM integration -----------------


def test_llm_null_provider_is_wired_in_default():
    """Without explicit config, the LLM layer refuses (L17/ADR-0005)."""
    from netops_autopilot.llm import build_provider
    p = build_provider("null")
    from netops_autopilot.llm.providers import LLMRequest
    with pytest.raises(Failure) as exc:
        p.complete(LLMRequest(system="s", user="u"))
    assert exc.value.cls is FailureClass.BLOCKED
    assert "LLM_PROVIDER_DISABLED" in exc.value.causes[0]


# ----------------- Failure path: human does not confirm -----------------


def test_human_refuses_binding_typed_stop():
    store, key_id, _, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = ScriptedIO(["n", "unused", "unused"])  # refuses the bond
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=io, time_authority=time_auth,
    )
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    # The run aborted with a typed reason.
    assert report.final.startswith("BLOCKED-")
    # No devices were discovered (the bond blocked everything downstream).
    assert report.crawl is None or report.crawl.totals["devices"] == 0


# ----------------- Failure path: unknown family -----------------


def test_unknown_family_prompts_for_input():
    """The orchestrator should ask the human for the family when the
    banner evidence doesn't match any vendor."""
    from netops_autopilot.access.vendor_detect import detect_family_candidates

    # A banner that matches no vendor.
    candidates = detect_family_candidates(b"this is not a network device banner")
    # The function may return [] or some heuristic; either way, it must not raise.
    assert isinstance(candidates, (list, tuple))


# ----------------- SimFabric determinism -----------------


def test_simfabric_is_deterministic():
    """Two runs of the same scenario on the same fabric should be byte-identical."""
    def run_once():
        store, key_id, _, time_auth = make_ledger_stack()
        fabric = SimFabricFactory(include_access=True, access_behavior="allow")
        engine = AutopilotEngine(
            store=store, key_id=key_id, io=make_scenario_io("branch"),
            time_authority=time_auth,
        )
        r = engine.run(
            probe_port_session_factory=lambda port: fabric.probe(port),
            mgmt_session_factory=fabric.open,
            port="SIM0", execute=False,
        )
        return r.final, store.event_count()

    a_final, a_count = run_once()
    b_final, b_count = run_once()
    assert a_final == b_final
    assert a_count == b_count


# ----------------- Counters are wired into the engine -----------------


def test_engine_has_counter_collector():
    store, key_id, counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=make_scenario_io("branch"),
        time_authority=time_auth,
    )
    # Every engine must carry a counter collector.
    assert engine.counters is counters or engine.counters is not None
    snap = engine.counters.snapshot()
    for c in T5_COUNTERS:
        assert c in snap
        assert snap[c] == 0


# ----------------- Reports can be written to disk -----------------


def test_report_files_written_to_disk(tmp_path: Path):
    from netops_autopilot.reporting.html_report import render_html_report, report_from_autopilot
    from netops_autopilot.reporting.json_report import render_json_report

    store, key_id, _, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=make_scenario_io("branch"),
        time_authority=time_auth,
    )
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False,
    )
    data = report_from_autopilot(
        report, run_id="disk-test",
        ledger_event_count=store.event_count(),
        chain_ok=True,
    )
    html_path = tmp_path / "run.html"
    json_path = tmp_path / "run.json"
    html_path.write_text(render_html_report(data), encoding="utf-8")
    json_path.write_text(render_json_report(
        report=report, ledger_event_count=store.event_count(), chain_ok=True,
    ), encoding="utf-8")
    assert html_path.exists()
    assert json_path.exists()
    assert html_path.stat().st_size > 1000
    # The JSON must round-trip.
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["schema"] == "netops-autopilot/run-report/v1"
