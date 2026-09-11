"""E30 Harness Runner (D0-10 §3/§6).

* Every scenario runs with a KNOWN ANSWER (expected facts/counters). A
  scenario that cannot run reports NOT_TESTED — never silently skipped.
* T5 counters are COMPUTED from the scenario's CounterCollector and ledger
  state — no manual attestation.
* ``gate_eligible`` scenarios contribute to the release gate (all T5
  counters must equal 0 AND the known answer must match); detection
  scenarios (FI-*) legitimately expect non-zero counters — their PASS means
  the platform OBSERVED what it must observe.
* Deterministic replay: every scenario runs twice; differing outputs ⇒ FAIL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.counters import T5_COUNTERS, CounterCollector


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    tier: str                                  # unit | fsm | integration | fi | e2e
    known_answer: dict                         # facts the run must produce
    gate_eligible: bool = False                # contributes to the release gate?
    expected_counters: Optional[dict] = None   # None ⇒ all ten must be ZERO


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    tier: str
    outcome: str                               # PASS | FAIL | NOT_TESTED
    mismatches: tuple[str, ...]
    counters: dict[str, int]
    replay_stable: bool


@dataclass(frozen=True)
class T5Report:
    scenarios: tuple[ScenarioResult, ...]
    counter_totals: dict[str, int]             # across gate-eligible scenarios
    release_gate: str                          # PASS | FAIL
    not_tested: tuple[str, ...]

    def to_text(self) -> str:
        lines = ["T5 EVALUATION REPORT (E30) — computed from runs, no attestation",
                 "=" * 72]
        for r in self.scenarios:
            mark = {"PASS": "✓", "FAIL": "✗", "NOT_TESTED": "…"}[r.outcome]
            lines.append(f"{mark} {r.scenario_id:<34} [{r.tier:<11}] {r.outcome}"
                         + (f" mismatches={list(r.mismatches)}" if r.mismatches else ""))
        lines.append("-" * 72)
        lines.append("GATE-ELIGIBLE T5 COUNTERS (must all be 0):")
        for name in T5_COUNTERS:
            value = self.counter_totals.get(name, 0)
            lines.append(f"  {name:<32} {value}")
        lines.append(f"NOT_TESTED (never silently skipped): {list(self.not_tested)}")
        lines.append(f"RELEASE GATE: {self.release_gate}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "scenarios": [r.__dict__ for r in self.scenarios],
            "counter_totals": self.counter_totals,
            "release_gate": self.release_gate,
            "not_tested": list(self.not_tested),
        }, indent=2)


#: scenario callable → (observed_facts: dict, counters: CounterCollector).
ScenarioFn = Callable[[], tuple[dict, CounterCollector]]


class HarnessRunner:
    def __init__(self, scenarios: dict[str, ScenarioFn]) -> None:
        self._scenarios = scenarios

    def run(self, specs: tuple[ScenarioSpec, ...]) -> T5Report:
        results: list[ScenarioResult] = []
        counter_totals = {name: 0 for name in T5_COUNTERS}
        not_tested: list[str] = []
        gate_failures: list[str] = []
        for spec in specs:
            fn = self._scenarios.get(spec.scenario_id)
            if fn is None:
                results.append(ScenarioResult(spec.scenario_id, spec.tier, "NOT_TESTED",
                                              ("no runner registered",), {}, True))
                not_tested.append(spec.scenario_id)
                continue
            run_a = self._safe_run(spec, fn)
            run_b = self._safe_run(spec, fn)
            if run_a.outcome == "NOT_TESTED":
                not_tested.append(spec.scenario_id)
                results.append(run_a)
                continue
            replay_stable = (run_a.mismatches == run_b.mismatches
                             and run_a.counters == run_b.counters)
            mismatches = run_a.mismatches + (() if replay_stable else ("REPLAY_UNSTABLE",))
            counters = run_a.counters
            expected = spec.expected_counters if spec.expected_counters is not None else {
                name: 0 for name in T5_COUNTERS}
            counter_mismatch = tuple(
                f"COUNTER {name} observed={counters.get(name, 0)} expected={want}"
                for name, want in expected.items() if counters.get(name, 0) != want)
            mismatches = mismatches + counter_mismatch
            outcome = "PASS" if not mismatches else "FAIL"
            results.append(ScenarioResult(spec.scenario_id, spec.tier, outcome,
                                          mismatches, counters, replay_stable))
            if spec.gate_eligible:
                for name in T5_COUNTERS:
                    counter_totals[name] += counters.get(name, 0)
                if outcome != "PASS":
                    gate_failures.append(spec.scenario_id)
        release = "PASS" if not gate_failures and all(v == 0 for v in counter_totals.values()) else "FAIL"
        return T5Report(scenarios=tuple(results), counter_totals=counter_totals,
                        release_gate=release, not_tested=tuple(sorted(set(not_tested))))

    def _safe_run(self, spec: ScenarioSpec, fn: ScenarioFn) -> ScenarioResult:
        try:
            facts, counters = fn()
        except Exception as exc:  # a scenario crash is a FAIL with cause, not silence
            if type(exc).__name__ == "ScenarioNotTestable":
                return ScenarioResult(spec.scenario_id, spec.tier, "NOT_TESTED", (str(exc),), {}, True)
            return ScenarioResult(spec.scenario_id, spec.tier, "FAIL",
                                  (f"SCENARIO_CRASH: {type(exc).__name__}: {exc}",), {}, False)
        mismatches: list[str] = []
        for key, want in spec.known_answer.items():
            got = facts.get(key, "<absent>")
            if got != want:
                mismatches.append(f"FACT {key} observed={got!r} expected={want!r}")
        for key, want in facts.items():
            if key not in spec.known_answer:
                mismatches.append(f"UNEXPECTED_FACT {key}={want!r} (not in known answer)")
        return ScenarioResult(spec.scenario_id, spec.tier,
                              "PASS" if not mismatches else "FAIL",
                              tuple(mismatches), counters.snapshot(), True)


class ScenarioNotTestable(Exception):
    """Raised by a scenario when its substrate is absent (⇒ NOT_TESTED)."""


def default_scenarios() -> dict[str, ScenarioFn]:
    """The v1 known-answer scenario catalog (all deterministic, sim-tier)."""

    def _scenario_crawl():
        from tests.support.simfabric import SimFabricFactory, make_ledger_stack
        from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
        from netops_autopilot.access.collector import Collector, SessionLockManager
        from netops_autopilot.core.budgets import CommandBudget
        from netops_autopilot.engines.claim_factory import ClaimFactory
        from netops_autopilot.engines.discovery_crawl import DiscoveryCrawlEngine
        from netops_autopilot.engines.link_evidence import LinkEvidenceEngine
        from netops_autopilot.parsers.catalog import default_registry
        from netops_autopilot.twin.twin import DigitalTwin

        store, key_id, counters, time_auth = make_ledger_stack()
        allowlist = CommandAllowlist(tuple(
            AllowlistEntry(template=t, cls="READ_ONLY") for t in
            ("show version", "show lldp neighbors detail", "show cdp neighbors detail")))
        registry = default_registry()
        twin = DigitalTwin(store, counters)
        links = LinkEvidenceEngine(lambda: __import__(
            "netops_autopilot.fsm.link_fsm", fromlist=["build_link_fsm"]).build_link_fsm(recorder=store, counters=counters))
        collector = Collector(store=store, key_id=key_id, allowlist=allowlist,
                              time_authority=time_auth, locks=SessionLockManager(),
                              default_budget=CommandBudget(max_retries=0))
        engine = DiscoveryCrawlEngine(store=store, twin=twin, collector=collector,
                                      parsers=registry, link_engine=links,
                                      claim_factory=ClaimFactory(store, registry))
        fabric = SimFabricFactory(include_access=True, access_behavior="allow")
        report = engine.crawl(
            seed_ref="seed-01", seed_family="cisco/ios-xe",
            session_factory=fabric, allowlist_of=lambda f: allowlist)
        facts = {
            "devices": report.totals["devices"],
            "commands": f"{report.totals['commands_collected']}/{report.totals['commands_planned']}",
            "chain_ok": store.verify_chain().ok,
        }
        return facts, counters

    def _scenario_intent_golden():
        from netops_autopilot.engines.blueprints import BLUEPRINTS, business_intent_from_blueprint
        from netops_autopilot.engines.intent_compiler import IntentCompiler
        from netops_autopilot.engines.service_graph import ServiceGraph

        counters = CounterCollector()
        bp = next(b for b in BLUEPRINTS if b.blueprint_id == "guest_office")
        req, missing = business_intent_from_blueprint(
            bp, answers={"wan_handoff": "x", "availability": "STANDARD", "growth": "flat"},
            requirement_text="guest wifi")
        intent = IntentCompiler(ServiceGraph.load_builtin()).compile(req)
        facts = {"status": intent.status, "rules": len(intent.rules),
                 "matrix_complete": IntentCompiler.matrix_is_complete(intent),
                 "missing_params": missing}
        return facts, counters

    def _scenario_autopilot_e2e():
        from netops_autopilot.autopilot.answer_script import answer_script
        from netops_autopilot.autopilot.orchestrator import AutopilotEngine
        from netops_autopilot.cli import ScriptedIO
        from tests.support.simfabric import SimFabricFactory, make_ledger_stack

        store, key_id, counters, time_auth = make_ledger_stack()
        fabric = SimFabricFactory(include_access=True, access_behavior="allow")
        engine = AutopilotEngine(
            store=store, key_id=key_id,
            io=ScriptedIO(answer_script(access_retry="n", intent="2",
                                      wan_handoff="x", growth="flat")),
            time_authority=time_auth)
        report = engine.run(
            probe_port_session_factory=lambda port: fabric.probe(port),
            mgmt_session_factory=fabric.open, port="SIM0", execute=False)
        facts = {"final": report.final,
                 "chain_ok": store.verify_chain().ok,
                 "phases": len(report.phases)}
        return facts, counters

    def _scenario_fi_forged_event():
        """FI-11: a forged/replayed event must be caught by chain verification."""
        from tests.support.simfabric import make_ledger_stack

        store, key_id, counters, time_auth = make_ledger_stack()
        from datetime import datetime, timezone
        from netops_autopilot.ledger.models import (
            ClockStatusEnum, CollectorIdentity, Event, EventType, OperatorIdentity)
        event = Event(type=EventType.CLI, device_id="edge-01", command_or_op="show version",
                      operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
                      collector_identity=CollectorIdentity(collector_id="c-0", key_id=key_id),
                      collected_at=datetime(2026, 9, 9, tzinfo=timezone.utc),
                      collector_clock_status=ClockStatusEnum.SYNCED)
        store.append_event(store.sign_event(event, key_id))
        first = store.verify_chain()
        # tamper: rewrite the stored payload byte history
        store._db.execute("UPDATE events SET payload_json = replace(payload_json,'show version','erase start')")
        store._db.commit()
        second = store.verify_chain()
        facts = {"before_tamper": first.ok, "after_tamper_detected": not second.ok,
                 "detection_reason": "" if second.ok else second.reason}
        return facts, counters

    return {
        "golden:crawl-sim-fabric": _scenario_crawl,
        "golden:intent-guest-isolation": _scenario_intent_golden,
        "golden:autopilot-e2e-staged": _scenario_autopilot_e2e,
        "fi:ledger-tamper": _scenario_fi_forged_event,
    }


DEFAULT_SPECS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec("golden:crawl-sim-fabric", "integration",
                 {"devices": 3, "commands": "6/6", "chain_ok": True}, gate_eligible=True),
    ScenarioSpec("golden:intent-guest-isolation", "unit",
                 {"status": "COMPILED", "rules": 17, "matrix_complete": True, "missing_params": []},
                 gate_eligible=True),
    ScenarioSpec("golden:autopilot-e2e-staged", "e2e",
                 {"final": "COMPLETE-STAGED", "chain_ok": True, "phases": 8}, gate_eligible=True),
    ScenarioSpec("fi:ledger-tamper", "fi",
                 {"before_tamper": True, "after_tamper_detected": True,
                  "detection_reason": "RECORD_HASH_MISMATCH"}, gate_eligible=False),
)
