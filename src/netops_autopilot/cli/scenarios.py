"""Built-in demo scenarios for the operator CLI.

Each scenario is a fully-scripted ``ConsoleIO`` answer set so the demo
runs deterministically, no hardware required. Scenarios exercise different
network shapes (branch office, leaf-spine, hotel guest WiFi, retail POS)
to validate the elicitation → intent compiler → design pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from ..cli import ScriptedIO
from ..autopilot.answer_script import QUESTION_KEYS, answers_keyed
from ..autopilot.orchestrator import OperatorIO


@dataclass(frozen=True)
class Scenario:
    """A canned operator scenario."""

    name: str
    description: str
    answers: dict[str, str]       # every answer, keyed by the question it answers
    blueprint_hint: str           # the ``intent`` answer
    expected_outcome: str         # "COMPLETE-STAGED" | "BLOCKED-*" — for harness


def _scenario(name: str, description: str, blueprint_hint: str, **kwargs) -> Scenario:
    """Build a Scenario whose answer list cannot drift out of question order.

    ``answers_keyed`` is the only place the answers are assembled, so a question
    added to the orchestrator changes ``QUESTION_KEYS`` and every scenario here
    at once — instead of leaving four hand-written lists one slot out of step.

    Keyed rather than ordered, because no ordering can be right for every run:
    the access-retry prompt is asked only when discovery found an unreachable
    device, so the number of questions is a property of the network, not of
    this file.
    """
    answers = answers_keyed(access_retry="y", intent=blueprint_hint, **kwargs)
    return Scenario(name=name, description=description, answers=dict(answers),
                    blueprint_hint=blueprint_hint, expected_outcome="COMPLETE-STAGED")


SCENARIOS: dict[str, Scenario] = {
    "branch": _scenario(
        name="Branch Office",
        description="Small branch: 1 router, 1 LAN, 1 guest VLAN, ISP DHCP.",
        blueprint_hint="branch office with VoIP",
        wan_handoff="ISP fiber DHCP handoff",
        availability="STANDARD",
        growth="+25% in 12 months",
    ),
    "leaf-spine": _scenario(
        name="Datacenter Leaf-Spine",
        description="2-spine, 4-leaf fabric; L3 boundary at the spine; HA enabled.",
        blueprint_hint="datacenter leaf-spine with BGP",
        wan_handoff="Two uplinks, BGP to upstream AS",
        availability="HIGH",
        growth="+50% in 18 months",
    ),
    "hotel": _scenario(
        name="Hotel Guest WiFi",
        description="Hotel: 1 router, staff VLAN + guest VLAN, captive portal, HIGH availability.",
        blueprint_hint="hotel with guest WiFi captive portal",
        wan_handoff="ISP fiber, static IP /30",
        availability="HIGH",
        growth="+40% in 24 months",
    ),
    "retail": _scenario(
        name="Retail POS",
        description="Retail store: 1 router, POS VLAN + back-office VLAN + guest, PCI isolation.",
        blueprint_hint="retail store with POS and guest WiFi",
        wan_handoff="ISP cable modem DHCP",
        availability="STANDARD",
        growth="+15% in 12 months",
    ),
}


def make_scenario_io(scenario_id: str) -> ScriptedIO:
    """Return a ScriptedIO bound to the given scenario.

    The scenario's ``answers`` are keyed by question, so they are handed over
    verbatim and cannot be spliced into the wrong place. Splicing used to
    place the free-form blueprint hint between two positional answers, and a
    question added before it silently shifted every later answer one slot.
    """
    sc = SCENARIOS.get(scenario_id)
    if sc is None:
        raise KeyError(
            f"unknown scenario: {scenario_id!r}. Available: {sorted(SCENARIOS)}")
    return ScriptedIO(dict(sc.answers))


def list_scenarios() -> list[tuple[str, str]]:
    """Return (id, description) pairs for the CLI."""
    return [(sid, sc.description) for sid, sc in SCENARIOS.items()]
