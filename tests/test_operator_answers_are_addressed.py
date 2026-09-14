"""The operator's answers are addressed by question, not by position.

The engine asks a data-dependent set of questions: the access-retry prompt is
asked only when discovery found a device it could not reach. So no positional
answer list can be correct for every network — the same list is one answer
short on a network with an unreachable device and one answer long on a network
without. Both were true at once in this tree: ``ANSWER_SLOTS`` declared the
apply confirmation first while the engine asks it last, and omitted the
physical-binding confirmation entirely.

The failures that followed were not hypothetical. Measured on the simulated
fabric, a positional script built by ``answer_script(apply=True)`` put the word
``BOND`` into the physical-binding confirmation, the run refused the cable, and
it ended ``BLOCKED-BLOCKED`` while the same answers addressed by name ended
``INCOMPLETE-APPLIED``. Thirteen call sites appended ``"BOND"`` to the end of a
list to compensate, and four tests asserted the compensating order.

Worse, the compensation was load-bearing in production: both runners in
``cli_main`` installed the chat's answers with ``ScriptedIO(list(answers))``,
which for a mapping yields its *keys* — so a chat-initiated run would have
answered every question with the name of the question.
"""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.answer_script import (
    ANSWER_SLOTS,
    QUESTION_KEYS,
    answer_script,
    answers_keyed,
)
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.core.failures import Failure
from netops_autopilot.simfabric import SimFabricFactory, make_ledger_stack


class _SpyIO(ScriptedIO):
    """Records the key of every question the engine asks, in order."""

    def __init__(self, answers) -> None:
        super().__init__(answers)
        self.asked: list[tuple[str, str | None]] = []

    def ask(self, question, key=None):
        self.asked.append(("ask", key))
        return super().ask(question, key=key)

    def confirm(self, question, key=None):
        self.asked.append(("confirm", key))
        return super().confirm(question, key=key)


def _run(answers, *, execute=True, fabric=None):
    store, key_id, _counters, ta = make_ledger_stack()
    fabric = fabric or SimFabricFactory()
    io = _SpyIO(answers)
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=ta)
    report = engine.run(
        probe_port_session_factory=fabric.probe,
        mgmt_session_factory=fabric, port="SIM0", execute=execute)
    return report, io, fabric


# ------------------------------------------------- the engine names its questions


def test_every_question_the_engine_asks_carries_a_key():
    """An unnamed question cannot be answered correctly by a machine.

    A human reads the prompt; a chat client, a web stream and a scenario all
    have to know *which* question they are answering. This is the invariant
    the rest of this file rests on, so it is asserted over a real run rather
    than asserted about the source text.
    """
    _report, io, _fabric = _run(answers_keyed(access_retry="n", intent="campus"))
    assert io.asked, "the engine asked nothing — the run never reached a question"
    unnamed = [kind for kind, key in io.asked if not key]
    assert not unnamed, f"{len(unnamed)} question(s) asked without a key"


def test_the_declared_order_is_the_order_the_engine_actually_asks():
    """``ANSWER_SLOTS`` claimed an order it did not have.

    It listed the apply confirmation first; the engine asks it last, at the
    execution gate. It also omitted the physical-binding confirmation, so every
    positional script was one answer short from the first question onward.
    """
    _report, io, _fabric = _run(answers_keyed(access_retry="n", intent="campus"))
    asked = tuple(key for _kind, key in io.asked)
    assert asked == ANSWER_SLOTS, (
        f"the engine asked {asked} but ANSWER_SLOTS declares {ANSWER_SLOTS}")


def test_answers_keyed_covers_every_question_the_engine_can_ask():
    _report, io, _fabric = _run(answers_keyed(access_retry="n", intent="campus"))
    asked = {key for _kind, key in io.asked}
    assert asked <= set(QUESTION_KEYS), asked - set(QUESTION_KEYS)
    assert set(answers_keyed(access_retry="n", intent="x")) == set(QUESTION_KEYS)


# ------------------------------------------------------- addressing, not ordering


def test_an_answer_follows_its_question_not_the_order_it_was_asked_in():
    answers = answers_keyed(access_retry="n", intent="campus",
                            wan_handoff="fiber /30", availability="HIGH")
    io = ScriptedIO(dict(answers))
    # asked backwards on purpose
    assert io.ask("growth?", key="growth") == "+25% in 12 months"
    assert io.ask("wan?", key="wan_handoff") == "fiber /30"
    assert io.ask("intent?", key="intent") == "campus"
    assert io.ask("avail?", key="availability") == "HIGH"
    assert io.ask("retry?", key="access_retry") == "n"


def test_an_unanswered_question_is_a_typed_failure_not_an_empty_string():
    """The old queue returned ``""`` when it ran dry.

    An empty answer is indistinguishable from an operator who answered
    "nothing", so a missing answer looked like a decision. ``dns_servers``
    legitimately accepts blank, which is exactly why a *missing* key has to be
    reported rather than defaulted.
    """
    answers = answers_keyed(access_retry="n", intent="campus")
    del answers["wan_handoff"]
    io = ScriptedIO(dict(answers))
    with pytest.raises(Failure) as excinfo:
        io.ask("Describe the WAN handoff: ", key="wan_handoff")
    assert "ANSWER_NOT_SCRIPTED:wan_handoff" in str(excinfo.value)


def test_a_question_asked_without_a_key_is_refused_when_answers_are_keyed():
    io = ScriptedIO(dict(answers_keyed(access_retry="n", intent="campus")))
    with pytest.raises(Failure) as excinfo:
        io.ask("Some new question?")
    assert "UNKEYED_QUESTION" in str(excinfo.value)


def test_an_explicit_blank_is_an_answer_and_a_missing_key_is_not():
    answers = answers_keyed(access_retry="n", intent="campus", dns_servers="")
    io = ScriptedIO(dict(answers))
    assert io.ask("DNS servers (blank = none): ", key="dns_servers") == ""


# ------------------------------------------------------------- the apply gate


def test_a_yes_does_not_unlock_the_apply_gate_and_says_so():
    """``bond_confirm="y"`` was this builder's own default and never worked.

    The gate unlocks only on the literal word ``BOND``, so the default staged
    everything and then ended ``BLOCKED-DENIED``. Every caller in the tree ran
    with ``execute=False`` and never reached the gate, so it was never
    exercised. An ambiguous yes is now refused at build time.
    """
    with pytest.raises(ValueError) as excinfo:
        answer_script(access_retry="n", intent="campus", bond_confirm="y")
    assert "BOND" in str(excinfo.value)
    assert answer_script(access_retry="n", intent="campus")[0] != "BOND"
    assert answers_keyed(access_retry="n", intent="campus",
                         apply=True)["bond_confirm"] == "BOND"


def test_a_keyed_run_really_applies_where_the_same_answers_positionally_did_not():
    """The measurement that started this: keyed applies, positional blocked.

    ``answer_script(apply=True)`` used to put ``BOND`` in the first slot, where
    the physical-binding confirmation consumed it; the run then refused the
    cable and ended ``BLOCKED-BLOCKED``. The same answers addressed by name
    reach the gate and apply.
    """
    keyed, _io, _fabric = _run(
        answers_keyed(access_retry="n", intent="campus", apply=True))
    assert (keyed.execution or {}).get("outcome") == "APPLIED", keyed.final
    assert keyed.final.endswith("APPLIED")

    positional, pio, _f = _run(
        list(answer_script(access_retry="n", intent="campus", apply=True)))
    assert (positional.execution or {}).get("outcome") == "APPLIED", (
        f"the positional script desynchronised: {pio.consumed}")


# ------------------------------------------------------------- the chat boundary


def test_the_chat_answers_survive_the_runner_boundary():
    """``ScriptedIO(list(mapping))`` yields the keys, not the answers.

    Both runners in ``cli_main`` installed the chat's answers that way, so a
    chat-initiated run would have answered every question with the *name* of
    the question — "intent" instead of "campus" — and still reported a
    completed run.
    """
    from netops_autopilot.chat.operator import ChatOperator

    operator = ChatOperator(store=None, runner=None)
    answers = operator._autopilot_answers(intent="campus", apply_bond=True)
    assert isinstance(answers, dict), "the chat must hand over keyed answers"
    assert answers["bond_confirm"] == "BOND"

    io = ScriptedIO(dict(answers))
    assert io.ask("What kind of network? ", key="intent") == "campus"
    # the defect this guards against, stated plainly
    assert list(answers) != list(answers.values())


def test_a_scenario_run_applies_end_to_end():
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    report, _fabric_io, _f = _run(dict(io._keyed), fabric=fabric)
    assert (report.execution or {}).get("outcome") == "APPLIED", report.final


def test_nothing_installs_a_keyed_answer_set_as_a_positional_list():
    """Repo-wide guard on the exact expression that broke the chat path.

    ``list(some_mapping)`` is its keys. Both runners in ``cli_main`` did
    ``ScriptedIO(list(answers))`` and the chat had started handing over a
    mapping, so every answer became the name of its question. The runners are
    local classes inside a function, so nothing can import and exercise them
    from here — this scans the tree instead, which is the only check that
    covers them.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"ScriptedIO\(\s*list\(", text):
            line = text[: match.start()].count("\n") + 1
            offenders.append(f"{path.relative_to(root)}:{line}")
    assert not offenders, (
        "a mapping keyed by question was flattened to its keys: "
        + ", ".join(offenders))
