"""Phase X — the chat actually executes the network the operator asked for.

The chat's ``apply <type>`` path was broken four ways at once, and every one of
them let it report success while doing something else:

* the answer list was a sixth hand-written copy, so when the access-retry prompt
  was added it landed one slot late and the *intent* question was answered with
  the router device — every chat-initiated run blocked at INTENT_ELICITATION;
* it hard coded blueprint "2" no matter what network the operator named;
* ``NETWORK_TYPES_*`` mapped "hotel", "retail" and "leaf-spine" to blueprint ids
  that do not exist, so ``elicit()`` returned UNKNOWN;
* the intent parser had a third, separate vocabulary list that was missing
  "campus", "data center" and "حرم", so those requests silently fell back to the
  default blueprint.

Diagnostics had their own defect: "the first COMPLETE device" became whichever
device sorts first alphabetically once discovery reached past the seed, so ping
ran from a switch that was never cabled to this computer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netops_autopilot.chat.operator import (
    ChatOperator,
    IntentVerb,
    _network_type_vocabulary,
    classify_intent,
)
from netops_autopilot.autopilot.answer_script import ANSWER_SLOTS, answer_script
from netops_autopilot.engines.blueprints import BLUEPRINTS
from netops_autopilot.engines.discovery_crawl import (
    CrawlReport,
    DeviceClass,
    DeviceResult,
    DeviceStatus,
)
from tests.support.simfabric import make_ledger_stack

BLUEPRINT_IDS = {b.blueprint_id for b in BLUEPRINTS}


# ============================================ 1. the vocabulary is one source
def test_every_network_type_names_a_blueprint_that_exists():
    """"hotel"/"retail"/"leaf-spine" were not blueprints, so elicit() said UNKNOWN."""
    for table_name, table in (("EN", ChatOperator.NETWORK_TYPES_EN),
                              ("AR", ChatOperator.NETWORK_TYPES_AR)):
        for phrase, blueprint_id in table.items():
            assert blueprint_id in BLUEPRINT_IDS, (
                f"NETWORK_TYPES_{table_name}[{phrase!r}] = {blueprint_id!r} "
                f"is not a blueprint; elicit() would return UNKNOWN and the "
                f"run would block. Known: {sorted(BLUEPRINT_IDS)}")


def test_every_network_type_phrase_is_recognised_by_the_parser():
    """The parser's vocabulary is derived, so it cannot miss a mapped phrase."""
    for phrase in _network_type_vocabulary():
        _verb, args = classify_intent(f"apply {phrase}")
        assert args.get("network_type") == phrase, (
            f"{phrase!r} is mapped to a blueprint but the intent parser does "
            f"not extract it, so the request falls back to the default")


def test_longest_phrase_wins():
    """"small office" must not be swallowed by "office"."""
    _verb, args = classify_intent("apply small office")
    assert args["network_type"] == "small office"
    _verb, args = classify_intent("apply office")
    assert args["network_type"] == "office"


# ================================================= 2. answers cannot desync
def test_answers_are_in_the_order_the_engine_asks():
    op = _operator()
    answers = op._autopilot_answers(intent="branch")
    assert len(answers) == len(ANSWER_SLOTS)
    assert answers == answer_script(access_retry="n", intent="branch")
    assert answers[ANSWER_SLOTS.index("intent")] == "branch"
    # a security-relevant prompt is answered explicitly, never left to default
    assert answers[ANSWER_SLOTS.index("access_retry")] == "n"


def test_apply_bond_is_appended_only_when_asked():
    op = _operator()
    assert "BOND" not in op._autopilot_answers(intent="branch")
    assert op._autopilot_answers(intent="branch", apply_bond=True)[-1] == "BOND"


def test_the_requested_type_reaches_the_answer_not_a_hardcoded_one():
    op = _operator()
    for phrase, expected in ChatOperator.NETWORK_TYPES_EN.items():
        answers = op._autopilot_answers(intent=phrase)
        assert answers[ANSWER_SLOTS.index("intent")] == phrase
        # and the phrase resolves to the blueprint the table promises
        from netops_autopilot.engines.blueprints import elicit
        assert elicit(expected).blueprint.blueprint_id == expected


# =============================================== 3. diagnostics use the seed
def _operator():
    store, _kid, _counters, _ta = make_ledger_stack()
    return ChatOperator(store=store, runner=None)


def _discovery(*specs):
    devices = tuple(
        DeviceResult(device_ref=ref, classification=cls, status=status)
        for ref, cls, status in specs)
    return CrawlReport(devices=devices, links=(), frontier_exhausted=True,
                       totals={"devices": len(devices)})


def test_diagnostics_run_from_the_seed_not_the_first_device_alphabetically():
    """`access-sw1` sorts before `seed-01` and is COMPLETE; it is not the seed."""
    op = _operator()
    op._ctx.last_discovery = _discovery(
        ("access-sw1", DeviceClass.NEIGHBOR_REACHED, DeviceStatus.COMPLETE),
        ("core-sw2", DeviceClass.NEIGHBOR_REACHED, DeviceStatus.COMPLETE),
        ("seed-01", DeviceClass.SEED, DeviceStatus.COMPLETE),
    )
    assert op._pick_diagnostic_source().device_ref == "seed-01"


def test_diagnostic_source_falls_back_honestly():
    op = _operator()
    op._ctx.last_discovery = _discovery(
        ("zz-switch", DeviceClass.NEIGHBOR_REACHED, DeviceStatus.COMPLETE),
        ("aa-switch", DeviceClass.NEIGHBOR_REACHED, DeviceStatus.COMPLETE),
    )
    # no seed: the first COMPLETE device, deterministically
    assert op._pick_diagnostic_source().device_ref == "zz-switch"


# ================================================ 4. no tooling debris in src
def test_no_edit_tool_artifacts_in_the_source_tree():
    """Upstream committed `</new_text><old_text>` fragments into operator.py.

    They sat inside comments so the code still parsed, which is exactly why
    nothing caught them. A marker from an editing tool in shipped source means
    an edit was applied by text substitution and never reviewed.
    """
    markers = ("</new_text>", "<old_text>", "</old_text>", "<new_text>")
    offenders = []
    for path in sorted(Path("src").rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in markers:
            if marker in text:
                offenders.append(f"{path}:{marker}")
    assert not offenders, offenders
