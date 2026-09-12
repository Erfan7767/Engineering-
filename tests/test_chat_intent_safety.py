"""A chat request must never be silently turned into a different action.

Two real misclassifications, both of which answered a question nobody asked:

* ``اربط هذا الفرع بالمقر`` ("connect this branch to HQ") matched the bare
  substring ``اربط`` and fired **BOND** — the identity-binding confirmation, a
  security-relevant human decision — on a sentence that never mentioned binding.
* ``أنشئ VLAN للموظفين`` / ``create a vlan for staff`` matched the bare
  substring ``vlan`` and were routed to **SHOW_VLANS**, a read-only verb. The
  operator asked for something to be built and got a table back.

The second is the more insidious of the two: it looks like an answer.

These tests pin the classification, and pin that the new CREATE_VLAN verb says
plainly that it changed nothing — because the chat's device runner is read-only
by construction, so a handler that reported OK would be lying.
"""

from __future__ import annotations

import pytest

from netops_autopilot.chat.operator import (
    ChatOperator,
    IntentVerb,
    ReplyStatus,
    classify_intent,
)
from tests.support.simfabric import make_ledger_stack


# ============================================== creation is not a read
@pytest.mark.parametrize("text", [
    "أنشئ VLAN للموظفين",
    "انشئ vlan 30",
    "أضف vlan للضيوف",
    "vlan جديد للضيوف",
    "create a vlan for staff",
    "add vlan 30",
    "create vlan guests",
])
def test_a_creation_request_is_not_routed_to_a_read_only_verb(text):
    verb, _args = classify_intent(text)
    assert verb is IntentVerb.CREATE_VLAN, (
        f"{text!r} classified as {verb.value} — the operator asked for "
        f"something to be built and would be shown a table instead")


@pytest.mark.parametrize("text", [
    "show vlans",
    "اعرض الشبكات المحلية",
    "vlan table",
    "show vlan",
])
def test_a_genuine_read_still_reads(text):
    """The fix must not break the verb it protects."""
    verb, _args = classify_intent(text)
    assert verb is IntentVerb.SHOW_VLANS, (text, verb.value)


# ============================================== BOND needs an explicit decision
@pytest.mark.parametrize("text", [
    "اربط هذا الفرع بالمقر",
    "اربط الشبكة الفرعية بالموجه",
    "اربط الجهازين ببعضهما",
])
def test_an_ordinary_link_request_does_not_fire_the_bond_gate(text):
    verb, _args = classify_intent(text)
    assert verb is not IntentVerb.BOND, (
        f"{text!r} fired BOND, the identity-binding confirmation, on a "
        f"sentence that never mentioned binding")


@pytest.mark.parametrize("text", [
    "أكد الربط",
    "تأكيد الربط",
    "اربط الجهاز بالكمبيوتر",
    "bond",
    "confirm binding",
])
def test_a_real_bond_confirmation_still_works(text):
    verb, _args = classify_intent(text)
    assert verb is IntentVerb.BOND, (text, verb.value)


# ============================================== the handler must not claim success
def _operator() -> ChatOperator:
    store, _kid, _counters, _ta = make_ledger_stack()
    return ChatOperator(store=store, runner=None)


@pytest.mark.parametrize("lang_text", ["أنشئ VLAN للموظفين", "create a vlan for staff"])
def test_create_vlan_reports_that_it_changed_nothing(lang_text):
    op = _operator()
    reply = op.handle(lang_text)
    assert reply.intent is IntentVerb.CREATE_VLAN
    assert reply.status is not ReplyStatus.OK, (
        "the chat's device runner is read-only, so a CREATE_VLAN that reports "
        "OK is claiming a change that never happened")
    assert reply.status is ReplyStatus.BLOCKED
    blob = f"{reply.summary} {reply.detail}".lower()
    # It must say so in as many words, not merely omit a success claim.
    assert ("nothing was created" in blob or "لم يُنشأ شيء" in blob
            or "لم ينشأ شيء" in blob), reply.detail


def test_create_vlan_names_what_it_understood():
    """Showing the parsed intent is what makes a refusal checkable."""
    op = _operator()
    reply = op.handle("add vlan 30")
    assert "30" in reply.detail, reply.detail


# ============================================== unknown is honest, not silent
def test_an_unrecognised_request_is_blocked_not_answered():
    op = _operator()
    reply = op.handle("اربط هذا الفرع بالمقر")
    assert reply.intent is IntentVerb.UNKNOWN
    assert reply.status is ReplyStatus.BLOCKED
    assert reply.summary, "an empty summary reads as silence"
