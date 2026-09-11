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
from ..autopilot.orchestrator import OperatorIO


@dataclass(frozen=True)
class Scenario:
    """A canned operator scenario."""

    name: str
    description: str
    answers: tuple[str, ...]
    blueprint_hint: str           # free-form answer for the elicitation question
    expected_outcome: str         # "COMPLETE-STAGED" | "BLOCKED-*" — for harness


# Each scenario's ``answers`` tuple is laid out as:
#   (bond_confirm, router_device, wan_handoff, availability, growth)
# The orchestrator asks for the bond confirm first, then the free-form
# intent (which we splice in via ``make_scenario_io``), then the four
# device-specific values from ``answers[1:]``.

SCENARIOS: dict[str, Scenario] = {
    "branch": Scenario(
        name="Branch Office",
        description="Small branch: 1 router, 1 LAN, 1 guest VLAN, ISP DHCP.",
        answers=(
            "y",
            "branch-01",
            "ISP fiber DHCP handoff",
            "STANDARD",
            "+25% in 12 months",
        ),
        blueprint_hint="small branch office with guest WiFi",
        expected_outcome="COMPLETE-STAGED",
    ),
    "leaf-spine": Scenario(
        name="Datacenter Leaf-Spine",
        description="2-spine, 4-leaf fabric; L3 boundary at the spine; HA enabled.",
        answers=(
            "y",
            "spine-01",
            "Two uplinks, BGP to upstream AS",
            "HIGH",
            "+50% in 18 months",
        ),
        blueprint_hint="datacenter leaf-spine with BGP",
        expected_outcome="COMPLETE-STAGED",
    ),
    "hotel": Scenario(
        name="Hotel Guest WiFi",
        description="Hotel: 1 router, staff VLAN + guest VLAN, captive portal, HIGH availability.",
        answers=(
            "y",
            "hotel-rtr",
            "ISP fiber, static IP /30",
            "HIGH",
            "+40% in 24 months",
        ),
        blueprint_hint="hotel with guest WiFi captive portal",
        expected_outcome="COMPLETE-STAGED",
    ),
    "retail": Scenario(
        name="Retail POS",
        description="Retail store: 1 router, POS VLAN + back-office VLAN + guest, PCI isolation.",
        answers=(
            "y",
            "retail-01",
            "ISP cable modem DHCP",
            "STANDARD",
            "+15% in 12 months",
        ),
        blueprint_hint="retail store with POS and guest WiFi",
        expected_outcome="COMPLETE-STAGED",
    ),
}


def make_scenario_io(scenario_id: str) -> ScriptedIO:
    """Return a ScriptedIO bound to the given scenario.

    The orchestrator asks questions in this order (from ``_phase_bond`` →
    ``_phase_boot_probe`` → ``_phase_elicit`` → ``_phase_design``):

    1. ``confirm``: bond (yes/no)        → ``"y"`` (from ``answers[0]``)
    2. ``ask``: intent (free-form)       → ``blueprint_hint`` (spliced in)
    3. ``ask``: router device            → ``answers[1]``
    4. ``ask``: WAN handoff              → ``answers[2]``
    5. ``ask``: availability             → ``answers[3]``
    6. ``ask``: growth                   → ``answers[4]``
    """
    if scenario_id not in SCENARIOS:
        raise KeyError(f"unknown scenario: {scenario_id!r}. Available: {list(SCENARIOS)}")
    sc = SCENARIOS[scenario_id]
    # Splice the blueprint_hint right after the bond confirm.
    answers = [sc.answers[0], sc.blueprint_hint] + list(sc.answers[1:])
    return ScriptedIO(answers)


def list_scenarios() -> list[tuple[str, str]]:
    return [(k, v.description) for k, v in SCENARIOS.items()]
