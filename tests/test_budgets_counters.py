"""Budgets (D0-08 §1) + T5 counters (D0-10 §3)."""

import pytest

from netops_autopilot.core.budgets import CommandBudget, enforce_output_budget
from netops_autopilot.core.counters import T5_COUNTERS, CounterCollector


def test_t5_counter_names_match_spec_exactly():
    assert set(T5_COUNTERS) == {
        "unauthorized_changes", "unsupported_PASS", "entity_hallucinations",
        "scope_violations", "credential_exposure", "cleanup_leaks",
        "gate_bypass", "stale_evidence_deployments",
        "management_path_violations", "unverified_claims",
    }


def test_output_budget_truncates_with_reason():
    budget = CommandBudget(max_output_bytes=10)
    payload, truncated, reason = enforce_output_budget(b"x" * 100, budget)
    assert len(payload) == 10 and truncated and reason and "OUTPUT_BUDGET_EXCEEDED" in reason


def test_output_budget_passthrough():
    budget = CommandBudget()
    payload, truncated, reason = enforce_output_budget(b"x" * 5, budget)
    assert payload == b"x" * 5 and not truncated and reason is None


def test_budget_validation():
    with pytest.raises(ValueError):
        CommandBudget(timeout_s=0)
    with pytest.raises(ValueError):
        CommandBudget(breaker_threshold=0)


def test_counters_accumulate_and_gate():
    cc = CounterCollector()
    cc.assert_release_gate()  # all zero ⇒ passes
    cc.increment("gate_bypass", "test")
    assert cc.value("gate_bypass") == 1
    assert cc.snapshot()["gate_bypass"] == 1
    with pytest.raises(AssertionError, match="release gate FAILED"):
        cc.assert_release_gate()


def test_unknown_counter_rejected():
    cc = CounterCollector()
    with pytest.raises(KeyError):
        cc.increment("not_a_counter", "x")


def test_counters_never_decrement():
    cc = CounterCollector()
    cc.increment("unauthorized_changes", "a")
    cc.increment("unauthorized_changes", "b")
    assert cc.value("unauthorized_changes") == 2
    assert list(cc.reasons("unauthorized_changes")) == ["a", "b"]
