"""Tests for the demo scenario presets."""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.answer_script import QUESTION_KEYS, answer_script
from netops_autopilot.cli.scenarios import (
    SCENARIOS,
    list_scenarios,
    make_scenario_io,
)
from netops_autopilot.cli import ScriptedIO


def test_all_scenarios_have_valid_shape():
    for sid, sc in SCENARIOS.items():
        assert sc.name
        assert sc.description
        assert sc.blueprint_hint
        assert sc.answers
        # Every question the orchestrator can ask is answered — no more, no
        # less. A positional list could only be checked for length, which is
        # meaningless when the number of questions depends on the network.
        assert set(sc.answers) == set(QUESTION_KEYS), (
            f"scenario {sid} answers {sorted(set(sc.answers) ^ set(QUESTION_KEYS))} "
            f"wrong")
        # The physical binding is confirmed; the apply gate is not.
        assert sc.answers["bond_physical"].strip().lower() in {"y", "yes"}, sid
        assert sc.answers["bond_confirm"] != "BOND", (
            f"scenario {sid} authorises an apply it never asked for")
        # the intent answer carries the blueprint hint; router names a real device
        assert sc.answers["intent"] == sc.blueprint_hint, sid
        assert sc.answers["router_device"] == "seed-01", sid


def test_list_scenarios_returns_pairs():
    items = list_scenarios()
    assert isinstance(items, list)
    assert all(isinstance(p, tuple) and len(p) == 2 for p in items)
    keys = {p[0] for p in items}
    assert keys == set(SCENARIOS.keys())


def test_make_scenario_io_known():
    io = make_scenario_io("branch")
    assert isinstance(io, ScriptedIO)
    assert io._keyed == dict(SCENARIOS["branch"].answers)
    assert io._answers == [], "a keyed scenario must not also queue positional answers"


def test_make_scenario_io_unknown_raises():
    with pytest.raises(KeyError):
        make_scenario_io("nonexistent-scenario-id")


def test_scenario_io_answers_each_question_by_name():
    """Asked out of order on purpose: the answer follows the question.

    The old test asked in the orchestrator's order and asserted each answer
    landed where expected. That could not fail for the reason it was written
    to catch — a question added anywhere shifts every later answer, and the
    test would have been updated to the new order along with the code. Asking
    in a scrambled order is only satisfiable if the answers are addressed.
    """
    sc = SCENARIOS["hotel"]
    io = make_scenario_io("hotel")
    router = io.ask("router?", key="router_device")
    intent = io.ask("intent?", key="intent")
    retry = io.ask("retry?", key="access_retry")
    bond = io.confirm("bond?", key="bond_physical")
    wan = io.ask("wan?", key="wan_handoff")
    avail = io.ask("avail?", key="availability")
    growth = io.ask("growth?", key="growth")

    assert bond is True
    assert retry == sc.answers["access_retry"]
    assert intent == sc.blueprint_hint
    # Phase V: the router answer is a device ref the simulated fabric actually
    # reports. It used to hold a site name ("hotel-rtr"), which the
    # orchestrator then fed to the WAN question and every answer after it
    # landed one slot late.
    assert router == "seed-01"
    assert wan == "ISP fiber, static IP /30"
    assert avail == "HIGH"
    assert growth == "+40% in 24 months"


def test_every_blueprint_hint_is_unambiguous():
    """A hint that matches two blueprints triggers a disambiguation question
    the script does not answer, shifting every later answer by one slot.

    This is the regression that made the demo print nonsense Q&A while still
    reporting success, so it is asserted for every scenario, not just hotel.
    """
    from netops_autopilot.engines.blueprints import elicit
    for sid, sc in SCENARIOS.items():
        result = elicit(sc.blueprint_hint)
        assert result.status == "MATCHED", (
            f"scenario {sid!r} hint {sc.blueprint_hint!r} elicited "
            f"{result.status} (candidates={result.candidates}); the scripted "
            f"answers would desynchronise")


def test_every_router_answer_is_a_real_device_ref():
    """The router slot must name a device the simulated fabric discovers."""
    for sid, sc in SCENARIOS.items():
        assert sc.answers["router_device"] == "seed-01", (
            f"scenario {sid!r} router answer {sc.answers['router_device']!r} is "
            f"not a device the simulated fabric reports")


def test_scenario_io_is_independent():
    """Two separate calls must not share state."""
    a = make_scenario_io("branch")
    b = make_scenario_io("retail")
    assert a is not b
    # Each has its own answer queue.
    assert a._keyed is not b._keyed
