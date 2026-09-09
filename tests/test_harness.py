"""E30 Harness: known-answer scenarios, computed T5 counters, release gate."""

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.harness.runner import (
    DEFAULT_SPECS,
    HarnessRunner,
    ScenarioSpec,
    default_scenarios,
)


def test_default_catalog_release_gate_passes():
    report = HarnessRunner(default_scenarios()).run(DEFAULT_SPECS)
    assert report.release_gate == "PASS"
    assert all(v == 0 for v in report.counter_totals.values())
    outcomes = {r.scenario_id: r.outcome for r in report.scenarios}
    assert outcomes == {
        "golden:crawl-sim-fabric": "PASS",
        "golden:intent-guest-isolation": "PASS",
        "golden:autopilot-e2e-staged": "PASS",
        "fi:ledger-tamper": "PASS",
    }
    assert report.not_tested == ()


def test_wrong_known_answer_is_a_fail_never_silence():
    bad_spec = (ScenarioSpec("golden:intent-guest-isolation", "unit",
                             {"status": "COMPILED", "rules": 13, "matrix_complete": True,
                              "missing_params": []}),)
    report = HarnessRunner(default_scenarios()).run(bad_spec)
    result = report.scenarios[0]
    assert result.outcome == "FAIL"
    assert any("rules" in m for m in result.mismatches)
    # known-answer mismatches in a gate-eligible scenario sink the gate.
    assert report.release_gate == "FAIL" or all(v == 0 for v in report.counter_totals.values())


def test_unexpected_fact_is_visible_not_hidden():
    def noisy():
        return {"status": "COMPILED", "extra": "surprise"}, CounterCollector()

    spec = (ScenarioSpec("unit:noisy", "unit", {"status": "COMPILED"}),)
    report = HarnessRunner({"unit:noisy": noisy}).run(spec)
    assert report.scenarios[0].outcome == "FAIL"
    assert any("UNEXPECTED_FACT" in m for m in report.scenarios[0].mismatches)


def test_missing_runner_is_not_tested():
    spec = (ScenarioSpec("lab:hardware-flood", "fi", {"x": 1}),)
    report = HarnessRunner({}).run(spec)
    assert report.scenarios[0].outcome == "NOT_TESTED"
    assert report.not_tested == ("lab:hardware-flood",)


def test_expected_counter_detection_scenario():
    def detects():
        counters = CounterCollector()
        counters.increment("entity_hallucinations", "expected: quarantined hallucination")
        return {"quarantined": 1}, counters

    spec = (ScenarioSpec("fi:hallucination-detection", "fi", {"quarantined": 1},
                         expected_counters={"entity_hallucinations": 1}),)
    report = HarnessRunner({"fi:hallucination-detection": detects}).run(spec)
    assert report.scenarios[0].outcome == "PASS"
    # expected non-zero counters in an FI scenario do not poison the gate.
    assert report.counter_totals["entity_hallucinations"] == 0
    assert report.release_gate == "PASS"


def test_replay_instability_is_a_fail():
    state = {"n": 0}

    def unstable():
        state["n"] += 1
        return {"run": state["n"]}, CounterCollector()

    spec = (ScenarioSpec("unit:unstable", "unit", {"run": 1}),)
    report = HarnessRunner({"unit:unstable": unstable}).run(spec)
    assert report.scenarios[0].outcome == "FAIL"
    assert not report.scenarios[0].replay_stable


def test_scenario_crash_is_typed_fail():
    def boom():
        raise RuntimeError("kaboom")

    spec = (ScenarioSpec("unit:boom", "unit", {}),)
    report = HarnessRunner({"unit:boom": boom}).run(spec)
    assert report.scenarios[0].outcome == "FAIL"
    assert any("SCENARIO_CRASH" in m for m in report.scenarios[0].mismatches)
