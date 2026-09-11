"""Tests for the demo scenario presets."""

from __future__ import annotations

import pytest

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


def test_list_scenarios_returns_pairs():
    items = list_scenarios()
    assert isinstance(items, list)
    assert all(isinstance(p, tuple) and len(p) == 2 for p in items)
    keys = {p[0] for p in items}
    assert keys == set(SCENARIOS.keys())


def test_make_scenario_io_known():
    io = make_scenario_io("branch")
    assert isinstance(io, ScriptedIO)
    # First answer is the bond confirm, second is the blueprint hint.
    assert io._answers[0] == "y"
    assert io._answers[1] == SCENARIOS["branch"].blueprint_hint


def test_make_scenario_io_unknown_raises():
    with pytest.raises(KeyError):
        make_scenario_io("nonexistent-scenario-id")


def test_scenario_io_consumes_answers_in_order():
    io = make_scenario_io("hotel")
    bond = io.confirm("bond?")
    intent = io.ask("intent?")
    router = io.ask("router?")
    wan = io.ask("wan?")
    avail = io.ask("avail?")
    growth = io.ask("growth?")
    # The bond confirm is a bool (True if "y" in answer)
    assert bond is True
    # Layout: [bond_confirm="y", blueprint_hint, router, wan, avail, growth]
    assert intent == SCENARIOS["hotel"].blueprint_hint
    assert router == "hotel-rtr"
    assert wan == "ISP fiber, static IP /30"
    assert avail == "HIGH"
    assert growth == "+40% in 24 months"


def test_scenario_io_is_independent():
    """Two separate calls must not share state."""
    a = make_scenario_io("branch")
    b = make_scenario_io("retail")
    assert a is not b
    # Each has its own answer queue.
    assert a._answers is not b._answers
