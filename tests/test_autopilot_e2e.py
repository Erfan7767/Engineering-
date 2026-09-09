"""Autopilot E2E — the operator's scenario through the simulated fabric.

Proves the full phase chain on deterministic scripted answers: BOND →
BOOT_PROBE → DISCOVERY_A → MAP → ELICIT → DESIGN → RENDER →
EXECUTION_GATE → REPORT, with ledger integrity and T5 cleanliness after
the whole run.
"""

from netops_autopilot.autopilot import Phase
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from tests.support.simfabric import SimFabricFactory, make_ledger_stack

ANSWERS = ["y", "2", "seed-01", "ISP fiber DHCP handoff", "STANDARD", "+25% in 12 months"]


def _run():
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(list(ANSWERS)), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False)
    return engine, store, report


def test_phase_chain_and_terminal_state():
    _engine, store, report = _run()
    phases = [p.phase for p in report.phases]
    assert phases == [Phase.BOND, Phase.BOOT_PROBE, Phase.DISCOVERY_A, Phase.TOPOLOGY_MAP,
                      Phase.INTENT_ELICITATION, Phase.DESIGN, Phase.RENDER, Phase.EXECUTION_GATE]
    assert report.final == "COMPLETE-STAGED"
    assert store.verify_chain().ok
    # T5 counters: the whole run must leave the release gate clean.
    assert all(v == 0 for v in _engine.counters.snapshot().values())


def test_discovery_map_and_honest_gaps():
    _engine, _store, report = _run()
    assert report.crawl is not None
    by_ref = {d.device_ref: d for d in report.crawl.devices}
    assert by_ref["seed-01"].status.value == "COMPLETE"
    assert by_ref["core-sw2"].status.value == "COMPLETE"
    assert by_ref["access-sw1"].status.value == "UNREACHABLE"   # the duplicate-device case, typed
    assert report.topology is not None
    assert any(g.startswith("DEVICE_UNREACHABLE access-sw1") for g in report.topology.gaps)
    # bidirectional pair reached the passive ceiling; nothing above it.
    states = {e.state for e in report.topology.edges}
    assert "DIRECT_NEIGHBOR_PROBABLE" in states
    assert "DIRECT_NEIGHBOR_CONFIRMED" not in states


def test_intent_design_and_preview():
    _engine, _store, report = _run()
    assert report.intent is not None and report.intent.status == "COMPILED"
    assert report.elicitation.blueprint.blueprint_id == "guest_office"
    design = report.design
    assert design is not None and not design.blocked
    roles = {r.device_ref: r.role for r in design.roles}
    assert roles["seed-01"] == "ROUTER"
    assert roles["access-sw1"] == "UNMANAGED_NEIGHBOR"
    # IR only for managed devices; every render is the honest PREVIEW label.
    assert set(report.renders) == {"seed-01", "core-sw2"}
    assert all(r.label == "PREVIEW_SEED_UNVERIFIED" for r in report.renders.values())


def test_execution_gate_enforces_law():
    _engine, _store, report = _run()
    assert report.execution["outcome"] == "STAGED_BLOCKED_BY_LAW"
    assert "CONFIG_ALLOWLIST_EMPTY" in report.execution["reason"]


def test_full_run_is_replay_deterministic():
    _e1, _s1, report_a = _run()
    _e2, _s2, report_b = _run()
    assert report_a.design == report_b.design
    assert report_a.topology.ascii == report_b.topology.ascii
    assert {k: v.to_text() for k, v in report_a.renders.items()} == \
           {k: v.to_text() for k, v in report_b.renders.items()}


def test_binding_refusal_stops_run():
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory()
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(["n"]), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open, port="SIM0", execute=False)
    assert report.final.startswith("BLOCKED")
    assert any("OPERATOR_DID_NOT_CONFIRM_BINDING" in str(p.detail) or
               "OPERATOR" in str(getattr(report, "final", "")) for p in report.phases)
