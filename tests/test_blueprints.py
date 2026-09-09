"""Blueprints + elicitation: deterministic, bilingual, fail-closed."""

from netops_autopilot.engines.blueprints import (
    BLUEPRINTS,
    business_intent_from_blueprint,
    elicit,
    menu,
)
from netops_autopilot.engines.intent_compiler import IntentCompiler
from netops_autopilot.engines.service_graph import ServiceGraph


def test_catalog_is_deterministic_and_unique():
    ids = [b.blueprint_id for b in BLUEPRINTS]
    assert len(ids) == len(set(ids))
    assert len(BLUEPRINTS) == 6


def test_exact_id_and_menu_number_match():
    assert elicit("branch").blueprint.blueprint_id == "branch"
    assert elicit("3").blueprint is BLUEPRINTS[2]


def test_arabic_keywords_match():
    assert elicit("مكتب صغير").blueprint.blueprint_id == "small_office"
    assert elicit("مركز بيانات").blueprint.blueprint_id == "datacenter"
    assert elicit("شبكة فرع").blueprint.blueprint_id == "branch"


def test_english_keywords_match():
    assert elicit("I want a data center network").blueprint.blueprint_id == "datacenter"
    assert elicit("guest wifi for visitors").blueprint.blueprint_id == "guest_office"


def test_unknown_is_unknown_never_a_default():
    result = elicit("quantum mesh of vibes")
    assert result.status == "UNKNOWN"
    assert result.question == menu()


def test_empty_is_unknown():
    assert elicit("   ").status == "UNKNOWN"


def test_ambiguity_blocks_with_survivors_only():
    # hits guest_office (keyword 'guest' inside 'guesthouse') AND campus via 'hq'
    result = elicit("hq guest network")
    assert result.status == "BLOCKED"
    assert set(result.candidates) == {"guest_office", "campus"}
    assert "Ambiguous" in result.question


def test_isolation_hint_subsets_deterministically():
    result = elicit("guest network with isolation")
    assert result.status == "MATCHED"
    assert result.blueprint.guest_isolation
    assert result.blueprint.blueprint_id == "guest_office"


def test_missing_required_parameters_are_blocking_codes():
    bp = next(b for b in BLUEPRINTS if b.blueprint_id == "small_office")
    request, missing = business_intent_from_blueprint(bp, answers={}, requirement_text="small office")
    assert request is None
    assert missing == ["wan_handoff"]


def test_full_path_compiles_through_intent_compiler():
    bp = next(b for b in BLUEPRINTS if b.blueprint_id == "guest_office")
    answers = {"wan_handoff": "dhcp from ISP", "availability": "STANDARD", "growth": "flat"}
    request, missing = business_intent_from_blueprint(bp, answers=answers, requirement_text="guest wifi")
    assert not missing and request is not None
    compiler = IntentCompiler(ServiceGraph.load_builtin())
    intent = compiler.compile(request)
    assert intent.status == "COMPILED"
    assert IntentCompiler.matrix_is_complete(intent)
    # guest isolation mandates 17 rules in the 4-zone §12 golden:
    assert len(intent.rules) == 17
