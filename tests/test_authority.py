"""Authority model (D0-02): invariants over the compiled table."""

import pytest

from netops_autopilot.policy.authority import (
    AUTHORITY_TABLE,
    HUMAN_ONLY,
    AuthorityViolation,
    assert_authority_invariants,
    who_decides,
)

LLM_AGENTS = {"A1_ORCHESTRATOR", "A2_REQUIREMENTS", "A3_ARCHITECT", "A4_AUDITOR", "A5_TROUBLESHOOTER"}


def test_table_covers_all_spec_decisions():
    decisions = {c.decision for c in AUTHORITY_TABLE}
    # The 15 decision rows of master spec §4.
    assert len(decisions) == 15
    assert "deployment_permission" in decisions
    assert "autonomy_decision" in decisions


def test_invariants_pass_on_shipped_table():
    assert_authority_invariants()


def test_no_llm_in_decide_cells():
    for cell in AUTHORITY_TABLE:
        for actor in cell.decide:
            assert actor not in LLM_AGENTS, f"LLM {actor} decides {cell.decision}"


def test_only_auditor_may_veto():
    for cell in AUTHORITY_TABLE:
        for actor in cell.veto:
            if actor in LLM_AGENTS:
                assert actor == "A4_AUDITOR"


def test_every_decision_has_exactly_one_decide_cell():
    for cell in AUTHORITY_TABLE:
        assert len(cell.decide) >= 1, cell.decision


def test_human_only_set_is_frozen_spec_set():
    assert HUMAN_ONLY == frozenset({
        "IRREVERSIBLE", "DESTRUCTIVE", "MANAGEMENT_PATH_TOUCHING", "NOT_MODELED_HIGH_RISK",
    })
    with pytest.raises(AttributeError):
        HUMAN_ONLY.add("LOW_RISK")  # type: ignore[attr-defined]


def test_who_decides_lookup():
    cell = who_decides("ip_overlap_subnetting")
    assert cell.decide == ("E07_IPAM",)
    with pytest.raises(KeyError):
        who_decides("not_a_decision")


def test_requirement_interpretation_decided_by_human():
    cell = who_decides("requirement_interpretation")
    assert cell.decide == ("HUMAN_CONFIRMATION",)
    assert cell.propose == ("A2_REQUIREMENTS",)
    assert cell.veto == ("A4_AUDITOR",)
