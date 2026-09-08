"""E19 Verification Engine — test matrix derived FROM the Network Intent
(FSM-2 guards 2.9/2.10, §15).

* The planner derives mandatory tests deterministically from the compiled
  intent: one connectivity expectation per zone×zone pair (resolved by
  rule precedence — carve-outs beat blanket denies) plus one SERVICE_UP
  test per required service. Same intent ⇒ byte-identical matrix, always;
* results are supplied by the caller/VerificationAdapter — a missing or
  unexecuted result is a typed BLOCKED gap, never a PASS (T1: only real
  evidence, TEST_ORIGIN tagged downstream);
* non-PASS outcomes never block the report mechanically — guard 2.10
  allows human acceptance per non-PASS, so the engine lists them for
  explicit human decision instead of hiding them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..core.failures import Failure, FailureClass
from .intent_compiler import NetworkIntent, RuleAction


class TestKind(str, Enum):
    __test__ = False  # pytest opt-out: domain class, not a test case

    CONNECTIVITY_ALLOW = "CONNECTIVITY_ALLOW"
    CONNECTIVITY_DENY = "CONNECTIVITY_DENY"
    SERVICE_UP = "SERVICE_UP"


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class TestSpec:
    __test__ = False  # pytest opt-out: domain class, not a test case

    test_id: str
    kind: TestKind
    src_zone: str   # "" for SERVICE_UP
    dst_zone: str   # service name for SERVICE_UP
    derivation: str  # which intent fact produced this test


@dataclass(frozen=True)
class TestResult:
    __test__ = False  # pytest opt-out: domain class, not a test case

    test_id: str
    outcome: Outcome
    evidence_id: str  # TEST_ORIGIN-tagged evidence, produced downstream

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("TEST_RESULT_EVIDENCE_EMPTY: a result without evidence is not a result (T1)",))


@dataclass(frozen=True)
class VerificationReport:
    total: int
    passed: tuple[str, ...]
    failed: tuple[str, ...]

    @property
    def all_pass(self) -> bool:
        return not self.failed and self.total > 0


class VerificationPlanner:
    """Intent → mandatory test matrix (guard 2.9)."""

    def derive(self, intent: NetworkIntent) -> tuple[TestSpec, ...]:
        specs: list[TestSpec] = []
        names = sorted({z.name for z in intent.zones})
        index = 0
        for src in names:
            for dst in names:
                rules = [r for r in intent.rules if r.src_zone == src and r.dst_zone == dst]
                if not rules:
                    raise Failure(cls=FailureClass.BLOCKED,
                                  causes=(f"INTENT_MATRIX_INCOMPLETE:{src}->{dst} — cannot derive tests",))
                effective = min(rules, key=lambda r: r.precedence)  # lowest precedence wins
                if effective.action is RuleAction.ALLOW:
                    specs.append(TestSpec(f"T{index:03d}:CONNECTIVITY_ALLOW:{src}->{dst}",
                                          TestKind.CONNECTIVITY_ALLOW, src, dst,
                                          f"rule[{effective.precedence}:{effective.reason}]"))
                else:
                    specs.append(TestSpec(f"T{index:03d}:CONNECTIVITY_DENY:{src}->{dst}",
                                          TestKind.CONNECTIVITY_DENY, src, dst,
                                          f"rule[{effective.precedence}:{effective.reason}]"))
                index += 1
        for service in intent.required_services:
            specs.append(TestSpec(f"T{index:03d}:SERVICE_UP:{service}",
                                  TestKind.SERVICE_UP, "", service,
                                  "required_services bring-up order"))
            index += 1
        return tuple(specs)


class VerificationEngine:
    """Specs + supplied results → report. Missing results ⇒ typed BLOCKED."""

    def evaluate(self, specs: tuple[TestSpec, ...], results) -> VerificationReport:
        by_id = {r.test_id: r for r in results}
        missing = tuple(sorted(s.test_id for s in specs if s.test_id not in by_id))
        if missing:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"TEST_RESULTS_MISSING:{','.join(missing)} — unexecuted tests are never PASS (T1)",))
        extra = tuple(sorted(tid for tid in by_id if tid not in {s.test_id for s in specs}))
        if extra:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"TEST_RESULTS_UNPLANNED:{','.join(extra)} — results outside the derived matrix are rejected",))
        passed = tuple(s.test_id for s in specs if by_id[s.test_id].outcome is Outcome.PASS)
        failed = tuple(s.test_id for s in specs if by_id[s.test_id].outcome is Outcome.FAIL)
        return VerificationReport(total=len(specs), passed=passed, failed=failed)

    @staticmethod
    def evidence_for_fsm2(report: VerificationReport,
                          human_acceptances: frozenset[str] = frozenset(),
                          evidence_id: str = "tests-ev") -> list[dict]:
        """Guard 2.10 shapes: all-pass, or non-pass + per-item human
        acceptance (identity lives on the acceptance evidence, §18)."""
        scope = "CONFIGURATION"
        if report.all_pass:
            return [{"scope": scope, "kind": "tests:all_pass",
                     "evidence_id": evidence_id, "status": "OK",
                     "detail": f"{len(report.passed)}/{report.total}"}]
        unaccepted = tuple(sorted(set(report.failed) - set(human_acceptances)))
        if unaccepted:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"NON_PASS_WITHOUT_HUMAN_ACCEPTANCE:{','.join(unaccepted)} (2.10)",))
        return [
            {"scope": scope, "kind": "tests:non_pass_present",
             "evidence_id": evidence_id, "status": "OK",
             "detail": ",".join(sorted(report.failed))},
            {"scope": scope, "kind": "tests:human_acceptance_per_non_pass",
             "evidence_id": evidence_id, "status": "OK",
             "detail": ",".join(sorted(human_acceptances))},
        ]
