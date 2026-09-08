"""E19 Verification Engine: intent-derived test matrix (guards 2.9/2.10)."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.intent_compiler import (
    BusinessIntentRequest, IntentCompiler, Zone, ZoneKind,
)
from netops_autopilot.engines.service_graph import ServiceGraph
from netops_autopilot.engines.verification import (
    Outcome, TestKind, TestResult, VerificationEngine, VerificationPlanner,
)


@pytest.fixture(scope="module")
def intent():
    compiler = IntentCompiler(ServiceGraph.load_builtin())
    req = BusinessIntentRequest(
        requirement_text="guest isolation",
        zones=(Zone("Internet", ZoneKind.WAN), Zone("Mgmt", ZoneKind.MGMT),
               Zone("Corp", ZoneKind.INTERNAL), Zone("Guests", ZoneKind.GUEST)),
        guest_isolation=True, internal_internet=True,
        availability_class="HIGH", growth_plan="+25%", intent_id="intent-fixed-v")
    return compiler.compile(req)


@pytest.fixture(scope="module")
def planner():
    return VerificationPlanner()


def results_all_pass(specs):
    return [TestResult(s.test_id, Outcome.PASS, f"ev-{i}") for i, s in enumerate(specs)]


# -------------------------------------------------------------- derivation
def test_matrix_covers_every_pair_plus_services(planner, intent):
    specs = planner.derive(intent)
    # 4 zones ⇒ 16 ordered pairs + 3 required services (dhcp, dns, internet_egress)
    assert len(specs) == 19
    pairs = {(s.src_zone, s.dst_zone) for s in specs if s.kind is not TestKind.SERVICE_UP}
    assert len(pairs) == 16
    services = {s.dst_zone for s in specs if s.kind is TestKind.SERVICE_UP}
    assert services == {"dhcp", "dns", "internet_egress"}


def test_carve_out_beats_blanket_deny_in_expectation(planner, intent):
    specs = {f"{s.src_zone}->{s.dst_zone}": s for s in planner.derive(intent)
             if s.kind is not TestKind.SERVICE_UP}
    assert specs["Guests->Corp"].kind is TestKind.CONNECTIVITY_ALLOW   # precedence 90 carve-out
    assert "rule[90:GUEST_BOOTSTRAP_SERVICES]" in specs["Guests->Corp"].derivation
    assert specs["Corp->Mgmt"].kind is TestKind.CONNECTIVITY_DENY      # DEFAULT_DENY
    assert specs["Guests->Internet"].kind is TestKind.CONNECTIVITY_ALLOW
    assert specs["Mgmt->Internet"].kind is TestKind.CONNECTIVITY_DENY


def test_test_ids_are_sequential_and_deterministic(planner, intent):
    a = planner.derive(intent)
    b = planner.derive(intent)
    assert a == b
    assert a[0].test_id == "T000:CONNECTIVITY_DENY:Corp->Corp" or a[0].test_id.startswith("T000:")
    for i, spec in enumerate(a):
        assert spec.test_id.startswith(f"T{i:03d}:")


# --------------------------------------------------------------- evaluation
def test_all_pass_requires_every_executed_result(planner, intent):
    specs = planner.derive(intent)
    report = VerificationEngine().evaluate(specs, results_all_pass(specs))
    assert report.all_pass is True
    assert report.total == 19 and report.failed == ()


def test_missing_results_are_never_pass(planner, intent):
    specs = planner.derive(intent)
    with pytest.raises(Failure) as exc:
        VerificationEngine().evaluate(specs, results_all_pass(specs)[:-2])
    assert "TEST_RESULTS_MISSING" in exc.value.causes[0]


def test_unplanned_results_are_rejected(planner, intent):
    specs = planner.derive(intent)
    extra = results_all_pass(specs) + [TestResult("T999:ROGUE", Outcome.PASS, "ev-x")]
    with pytest.raises(Failure) as exc:
        VerificationEngine().evaluate(specs, extra)
    assert "TEST_RESULTS_UNPLANNED" in exc.value.causes[0]


def test_result_without_evidence_is_not_a_result():
    with pytest.raises(Failure) as exc:
        TestResult("T000:x", Outcome.PASS, "")
    assert "TEST_RESULT_EVIDENCE_EMPTY" in exc.value.causes[0]


def test_failures_are_listed_not_hidden(planner, intent):
    specs = planner.derive(intent)
    results = results_all_pass(specs)
    results[0] = TestResult(specs[0].test_id, Outcome.FAIL, "ev-fail")
    report = VerificationEngine().evaluate(specs, results)
    assert report.all_pass is False
    assert report.failed == (specs[0].test_id,)


# ----------------------------------------------------- guard 2.10 evidence
def test_all_pass_evidence_shape(planner, intent):
    specs = planner.derive(intent)
    report = VerificationEngine().evaluate(specs, results_all_pass(specs))
    evs = VerificationEngine.evidence_for_fsm2(report)
    assert [e["kind"] for e in evs] == ["tests:all_pass"]


def test_non_pass_requires_human_acceptance_per_item(planner, intent):
    specs = planner.derive(intent)
    results = results_all_pass(specs)
    results[1] = TestResult(specs[1].test_id, Outcome.FAIL, "ev-f")
    results[2] = TestResult(specs[2].test_id, Outcome.FAIL, "ev-f2")
    report = VerificationEngine().evaluate(specs, results)
    with pytest.raises(Failure) as exc:
        VerificationEngine.evidence_for_fsm2(report)
    assert "NON_PASS_WITHOUT_HUMAN_ACCEPTANCE" in exc.value.causes[0]
    evs = VerificationEngine.evidence_for_fsm2(
        report, human_acceptances=frozenset({specs[1].test_id, specs[2].test_id}))
    assert [e["kind"] for e in evs] == ["tests:non_pass_present",
                                         "tests:human_acceptance_per_non_pass"]
