"""Tests for the demo scenario presets."""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.answer_script import ANSWER_SLOTS, answer_script
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
        # First answer must be the binding confirm "y".
        assert sc.answers[0].strip().lower() in {"y", "yes"}, f"scenario {sid} must start with bond confirm"
        assert len(sc.answers) == len(ANSWER_SLOTS), (
            f"scenario {sid} has {len(sc.answers)} answers for "
            f"{len(ANSWER_SLOTS)} question slots")
        # intent slot carries the blueprint hint; router slot names a real device.
        assert sc.answers[ANSWER_SLOTS.index("intent")] == sc.blueprint_hint, sid
        assert sc.answers[ANSWER_SLOTS.index("router_device")] == "seed-01", sid


def test_list_scenarios_returns_pairs():
    items = list_scenarios()
    assert isinstance(items, list)
    assert all(isinstance(p, tuple) and len(p) == 2 for p in items)
    keys = {p[0] for p in items}
    assert keys == set(SCENARIOS.keys())


def test_make_scenario_io_known():
    io = make_scenario_io("branch")
    assert isinstance(io, ScriptedIO)
    assert io._answers == list(SCENARIOS["branch"].answers)


def test_make_scenario_io_unknown_raises():
    with pytest.raises(KeyError):
        make_scenario_io("nonexistent-scenario-id")


def test_scenario_io_consumes_answers_in_order():
    io = make_scenario_io("hotel")
    bond = io.confirm("bond?")
    retry = io.ask("retry?")
    intent = io.ask("intent?")
    router = io.ask("router?")
    wan = io.ask("wan?")
    avail = io.ask("avail?")
    growth = io.ask("growth?")
    # The bond confirm is a bool (True if "y" in answer)
    assert bond is True
    # Layout: [bond, access_retry, blueprint_hint, router, wan, avail, growth]
    assert retry == SCENARIOS["hotel"].answers[ANSWER_SLOTS.index("access_retry")]
    assert intent == SCENARIOS["hotel"].blueprint_hint
    # Phase V: answers[1] is the ROUTER DEVICE, i.e. a device ref the
    # simulated fabric actually reports. It used to hold a site name
    # ("hotel-rtr"), which the orchestrator then fed to the WAN question and
    # every answer after it landed one slot late.
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
        i = ANSWER_SLOTS.index("router_device")
        assert sc.answers[i] == "seed-01", (
            f"scenario {sid!r} router answer {sc.answers[i]!r} is not a device "
            f"the simulated fabric reports")


def test_scenario_io_is_independent():
    """Two separate calls must not share state."""
    a = make_scenario_io("branch")
    b = make_scenario_io("retail")
    assert a is not b
    # Each has its own answer queue.
    assert a._answers is not b._answers
