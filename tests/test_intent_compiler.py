"""E08 Intent Compiler: §12 mandatory guest-isolation example, blocking
questions, complete matrix, deterministic service ordering."""

import pytest

from netops_autopilot.engines.intent_compiler import (
    BlockingQuestion,
    BusinessIntentRequest,
    IntentCompiler,
    PolicyRule,
    RuleAction,
    Zone,
    ZoneKind,
)
from netops_autopilot.engines.service_graph import ServiceGraph


@pytest.fixture(scope="module")
def compiler():
    return IntentCompiler(ServiceGraph.load_builtin())


SITE_ZONES = (
    Zone("Internet", ZoneKind.WAN),
    Zone("Mgmt", ZoneKind.MGMT),
    Zone("Corp", ZoneKind.INTERNAL),
    Zone("Guests", ZoneKind.GUEST),
)


def full_request(**over):
    base = dict(
        requirement_text="الضيوف لا يصلون للسيرفرات; الموظفون يحتاجون إنترنت",
        zones=SITE_ZONES,
        guest_isolation=True,
        internal_internet=True,
        availability_class="HIGH",
        growth_plan="+25% users in 12 months",
        intent_id="intent-fixed-001",
    )
    base.update(over)
    return BusinessIntentRequest(**base)


# ------------------------------------------------- §12 mandatory example
def test_guest_isolation_example_produces_the_four_mandated_decisions(compiler):
    intent = compiler.compile(full_request())
    assert intent.status == "COMPILED"
    rules = {(r.src_zone, r.dst_zone, r.action, r.services): r.reason for r in intent.rules}

    # 1. Guest → Internet ALLOW
    assert rules[("Guests", "Internet", RuleAction.ALLOW, ())] == "GUEST_INTERNET_EGRESS"
    # 2. Guest → Internal DENY (blanket)
    assert rules[("Guests", "Corp", RuleAction.DENY, ())] == "GUEST_ISOLATION_INTERNAL"
    # 3. Guest → DNS/DHCP ALLOW (service carve-out)
    assert rules[("Guests", "Corp", RuleAction.ALLOW, ("dns", "dhcp"))] == "GUEST_BOOTSTRAP_SERVICES"
    # 4. Guest → Mgmt DENY
    assert rules[("Guests", "Mgmt", RuleAction.DENY, ())] == "GUEST_ISOLATION_MGMT"


def test_service_carve_out_beats_blanket_deny_by_precedence(compiler):
    intent = compiler.compile(full_request())
    pair = IntentCompiler.effective_rules_for_pair(intent, "Guests", "Corp")
    assert [r.precedence for r in pair] == [90, 110]
    assert pair[0].action is RuleAction.ALLOW and pair[0].services == ("dns", "dhcp")
    assert pair[1].action is RuleAction.DENY and pair[1].services == ()


def test_no_vlan_or_ip_decisions_before_policy_matrix(compiler):
    """§12: the four decisions precede ANY VLAN/IP choice — structurally
    verified: PolicyRule carries no addressing fields at all."""
    intent = compiler.compile(full_request())
    allowed_fields = {"precedence", "src_zone", "dst_zone", "action", "services", "reason"}
    for rule in intent.rules:
        assert set(rule.__dataclass_fields__) == allowed_fields


def test_matrix_is_complete_with_default_deny(compiler):
    intent = compiler.compile(full_request())
    assert IntentCompiler.matrix_is_complete(intent)
    # 4 zones ⇒ 16 ordered pairs; count explicit structure:
    #   6 explicit guest/egress rules + 3 intra-zone + 8 DEFAULT_DENY = 17
    assert len(intent.rules) == 17
    default_denies = [r for r in intent.rules if r.reason == "DEFAULT_DENY"]
    assert len(default_denies) == 8
    # WAN ingress from anywhere is never allowed by default: only zones
    # WITHOUT an explicit egress rule may appear as src in DEFAULT_DENY→Internet.
    for rule in default_denies:
        if rule.dst_zone == "Internet":
            assert rule.src_zone not in {"Corp", "Guests"}


def test_rule_set_is_deterministic(compiler):
    a = compiler.compile(full_request())
    b = compiler.compile(full_request())
    assert a.rules == b.rules
    assert a.required_services == b.required_services


def test_required_services_in_bring_up_order(compiler):
    intent = compiler.compile(full_request())
    # dns + dhcp + internet_egress; egress depends on dns ⇒ dns precedes it
    assert list(intent.required_services) == ["dhcp", "dns", "internet_egress"]


def test_dot1x_adds_radius_chain_in_order(compiler):
    intent = compiler.compile(full_request(dot1x_required=True))
    services = list(intent.required_services)
    assert "radius" in services and "dot1x" in services
    assert services.index("ntp") < services.index("radius")
    assert services.index("dns") < services.index("radius")
    assert services.index("radius") < services.index("dot1x")


# ------------------------------------------------------- blocking questions
def test_no_zones_blocks_with_question(compiler):
    intent = compiler.compile(full_request(zones=()))
    assert intent.status == "BLOCKED"
    assert intent.rules == ()  # no guessing while blocked (L01)
    # full_request supplies availability+growth ⇒ only the zone gap fires:
    assert {q.code for q in intent.blocking_questions} == {"BQ-NO-ZONES"}


def test_all_intake_gaps_reported_together(compiler):
    """Every gap raises its blocking question in one pass (no drip-feeding)."""
    bare = BusinessIntentRequest(requirement_text="new site", zones=(), intent_id="intent-fixed-002")
    intent = compiler.compile(bare)
    codes = {q.code for q in intent.blocking_questions}
    assert {"BQ-NO-ZONES", "BQ-AVAILABILITY-MISSING", "BQ-GROWTH-MISSING"} <= codes
    assert all(isinstance(q, BlockingQuestion) for q in intent.blocking_questions)


def test_guest_flag_without_guest_zone_blocks(compiler):
    zones = tuple(z for z in SITE_ZONES if z.kind is not ZoneKind.GUEST)
    intent = compiler.compile(full_request(zones=zones))
    assert intent.status == "BLOCKED"
    assert "BQ-GUEST-FLAG-NO-ZONE" in {q.code for q in intent.blocking_questions}


def test_missing_wan_zone_blocks_when_egress_needed(compiler):
    zones = tuple(z for z in SITE_ZONES if z.kind is not ZoneKind.WAN)
    intent = compiler.compile(full_request(zones=zones))
    assert "BQ-NO-EGRESS" in {q.code for q in intent.blocking_questions}


def test_availability_and_growth_questions_are_blocking(compiler):
    intent = compiler.compile(full_request(availability_class=None, growth_plan=None))
    codes = {q.code for q in intent.blocking_questions}
    assert {"BQ-AVAILABILITY-MISSING", "BQ-GROWTH-MISSING"} <= codes
    invalid = compiler.compile(full_request(availability_class="ULTRA"))
    assert "BQ-AVAILABILITY-INVALID" in {q.code for q in invalid.blocking_questions}


def test_no_guest_isolation_still_yields_complete_matrix(compiler):
    intent = compiler.compile(full_request(guest_isolation=False))
    assert intent.status == "COMPILED"
    assert IntentCompiler.matrix_is_complete(intent)
    assert not any(r.reason.startswith("GUEST") for r in intent.rules)
    assert any(r.reason == "INTERNAL_INTERNET_EGRESS" for r in intent.rules)
