"""A request to change the network is never answered by a read.

The chat classified intents by scanning for pattern substrings in table order,
and SHOW_DEVICES registers the bare noun "الأجهزة". So "أعد إعداد هذه الأجهزة" —
reconfigure these devices — matched on the noun and came back with a device
listing. That is the worst shape a wrong answer can take: it looks like a
response, so the operator has no way to see that nothing was done.

Two things are pinned here. The specific phrasings, and the invariant behind
them: no read-only intent may claim a message that carries a change verb. The
invariant is checked against the whole pattern catalogue, not one entry, because
the next bare noun added to a SHOW_* list would reintroduce exactly this.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.chat.device_runner import DeviceCommandRunner
from netops_autopilot.chat.operator import (
    ChatOperator,
    IntentVerb,
    ReplyStatus,
    carries_write_verb,
)
from netops_autopilot.engines.discovery_crawl import (
    DeviceClass,
    DeviceResult,
    DeviceStatus,
)
from netops_autopilot.specs_data import specs_data_dir

from .support.simfabric import SimFabricFactory, make_ledger_stack


@pytest.fixture
def op():
    store, key_id, _counters, _ta = make_ledger_stack()
    fabric = SimFabricFactory()
    allowlist = CommandAllowlist.load_dir(specs_data_dir("allowlists"))
    runner = DeviceCommandRunner(session_factory=lambda r: fabric.open(r, ()),
                                 allowlist=allowlist, store=store)
    operator = ChatOperator(store=store, runner=None, device_runner=runner,
                            allowlist=allowlist)
    operator.context.last_discovery = SimpleNamespace(devices=(DeviceResult(
        device_ref="seed-01", classification=DeviceClass.SEED,
        status=DeviceStatus.COMPLETE, mgmt_addresses=("10.0.0.1",)),))
    return operator


# --------------------------------------------------------------- the phrasings
@pytest.mark.parametrize("message", [
    "أعد إعداد هذه الأجهزة",
    "اربط هذه الأجهزة بالطريقة المناسبة",
    "reconfigure these devices",
    "connect these devices properly",
])
def test_a_change_request_is_refused_not_answered_with_a_read(op, message):
    reply = op.handle(message)
    assert reply.status is ReplyStatus.BLOCKED, (
        f"{message!r} was answered instead of refused")
    assert not reply.intent.value.startswith("show_"), (
        f"{message!r} was answered by the read-only intent {reply.intent.value}")
    if reply.data.get("detected_write_verb"):
        # The request matched a read-only action, and the operator is told which
        # one was declined — understood, and deliberately not executed.
        assert reply.data["fallback_read_only_intent"].startswith("show_")
        assert ("لم يُغيَّر شيء" in reply.summary
                or "nothing was changed" in reply.summary)
    else:
        # Nothing matched at all, including a read. Still a refusal with a
        # reason rather than a plausible-looking answer.
        assert reply.summary


def test_a_create_request_with_a_plural_noun_is_still_a_create(op):
    """"أنشئ VLANs" used to fall to SHOW_VLANS: the matcher word-bounds Latin
    patterns, so the singular "vlan" does not match "vlans", and the bare plural
    registered under SHOW_VLANS won."""
    reply = op.handle("أنشئ VLANs المطلوبة")
    assert reply.intent is IntentVerb.CREATE_VLAN, reply.intent
    assert not reply.intent.value.startswith("show_")


# ------------------------------------------------------------- the invariant
def test_no_read_only_pattern_claims_a_message_carrying_a_change_verb():
    """Catalogue-wide: for every change verb and every read-only intent, a
    message built from that verb plus the intent's own trigger words must not
    classify as that read-only intent.

    This is what stops the next bare noun added to a SHOW_* list from silently
    reintroducing the defect, without anyone having to think of the phrasing.
    """
    from netops_autopilot.chat import operator as mod

    offending: list[tuple[str, str, str]] = []
    for patterns in (mod._AR_PATTERNS, mod._EN_PATTERNS):
        for verb, words in patterns:
            if not verb.value.startswith("show_"):
                continue
            for word in words:
                # A change verb in front of the intent's own trigger words: the
                # exact shape that used to be claimed by the noun.
                probe = (f"أعد {word}" if not word.isascii()
                         else f"reconfigure {word}")
                assert carries_write_verb(probe), probe   # the probe must ask
                got, _args = mod.classify_intent(probe)
                if got.value.startswith("show_"):
                    offending.append((probe, word, got.value))
    assert not offending, (
        "a read-only intent claims a message that asks for a change: "
        f"{offending}")


def test_write_verb_detection_is_whole_word_not_substring():
    """A substring scan would flag "غير" inside an unrelated word."""
    assert carries_write_verb("أعد إعداد هذه الأجهزة") == "أعد"
    assert carries_write_verb("create a vlan for staff") == "create"
    # "تغيير" contains "غير" but is a noun, not the imperative.
    assert carries_write_verb("ما هو تغيير الإعدادات") is None
    assert carries_write_verb("اعرض الأجهزة") is None


# --------------------------------------------------------------- no regression
@pytest.mark.parametrize("message,expected", [
    ("اعرض الأجهزة", IntentVerb.SHOW_DEVICES),
    ("اعرض خريطة الشبكة", IntentVerb.SHOW_TOPOLOGY),
    ("اكتشف جميع الأجهزة الموجودة", IntentVerb.SHOW_DEVICES),
    ("show devices", IntentVerb.SHOW_DEVICES),
])
def test_read_only_requests_still_work(op, message, expected):
    reply = op.handle(message)
    assert reply.intent is expected, (message, reply.intent)
    assert reply.status is not ReplyStatus.BLOCKED or reply.summary, (
        "a refusal must carry its reason")


def test_when_a_read_would_have_answered_the_refusal_names_it(op):
    """The case that motivated the guard, asserted outright rather than left to
    a branch inside a parametrised test."""
    reply = op.handle("أعد إعداد هذه الأجهزة")
    assert reply.data["detected_write_verb"] == "أعد"
    assert reply.data["fallback_read_only_intent"] == "show_devices"
    assert "show_devices" in reply.summary
