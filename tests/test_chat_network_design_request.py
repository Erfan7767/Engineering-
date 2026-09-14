""""Build me a network with staff and guests" is an answerable question.

The chat could design and apply a whole network, but only through a command
whose vocabulary it had invented for itself: ``طبق guest_office``. The way an
operator actually asks — "أنشئ شبكة موظفين وضيوف" — classified as UNKNOWN and
was refused, because the requirement was carried in zone words (staff,
guests) rather than in a blueprint name. The refusal was safe and it was
still a refusal to do the job.

Worse, the command the chat *did* offer was one it could not parse back:
``guest_office`` was read as the shorter phrase ``office`` inside it, the
Arabic table had no ``office``, and the run died at INTENT_ELICITATION —
after which the chat answered ``OK — applied``.

Three things are pinned here:

1. a design request is recognised, its zones are read, and the blueprints
   that can actually build those zones are offered — derived from
   ``BLUEPRINTS``, never from a hand-written list;
2. every label the operator offers is understood by the parser that emitted
   it;
3. the reply states what the run did. ``report.final`` is the engine's own
   verdict; ``execution["outcome"]`` alone was not enough to tell an applied
   network from a run that never sent anything.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.chat.operator import (
    ChatOperator,
    IntentVerb,
    ReplyStatus,
    _ZONE_WORDS,
    _network_type_vocabulary,
    blueprint_ids,
    candidate_blueprints,
    classify_intent,
    is_design_request,
    named_zones,
)
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.access.executor import ChangeOutcome, ChangeRecord
from netops_autopilot.engines.blueprints import BLUEPRINTS
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _change_record(device_ref: str, outcome: str) -> dict:
    """A change record in the shape the orchestrator really stores.

    ``execution["change_records"]`` entries are ``ChangeRecord.to_dict()``,
    which is where ``applied_count``/``command_count`` come from. Hand-writing
    the dict produced records the renderer could not read.
    """
    from datetime import datetime, timezone
    return ChangeRecord(
        device_ref=device_ref, run_id="t", outcome=ChangeOutcome(outcome),
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ).to_dict()


# ======================================= 1. the request is recognised


@pytest.mark.parametrize("text", [
    "أنشئ شبكة موظفين وضيوف",
    "أنشئ شبكة",
    "أنشئ شبكة للموظفين والضيوف مع عزل",
    "أعد شبكة مركز بيانات",
    "صمم شبكة مكتب",
    "create a network with staff and guests",
    "build me a branch network",
    "design a guest office network",
])
def test_a_request_to_build_a_network_is_a_design_request(text):
    assert is_design_request(text) is True
    verb, args = classify_intent(text)
    assert verb is IntentVerb.DESIGN
    assert "design_request" in args


@pytest.mark.parametrize("text,expected", [
    # A read about the network must stay a read. "أريد" is deliberately not
    # a design verb: precision costs a phrasing, a false positive costs a
    # change to the network.
    ("أريد حالة الشبكة", False),
    ("show network topology", False),
    ("what is the network status", False),
    # One object, not a network.
    ("أنشئ VLAN للموظفين", False),
    ("اعزل الضيوف عن الموظفين", False),
    # Already an explicit apply; the design path must not steal it.
    ("طبق مكتب", False),
    ("apply branch", False),
])
def test_requests_that_are_not_design_requests_are_untouched(text, expected):
    assert is_design_request(text) is expected


def test_a_design_request_that_named_a_zone_is_not_misrouted_to_isolate():
    """"...موظفين والضيوف مع عزل" used to classify as ISOLATE with no args.

    ``عزل`` is a trailing qualifier on a request to build a network; the
    leading verb decides, and there were never two zones to isolate.
    """
    verb, args = classify_intent("أنشئ شبكة للموظفين والضيوف مع عزل")
    assert verb is IntentVerb.DESIGN
    assert set(args["design_request"]["zones"]) == {"users", "guest"}


# ======================================= 2. zones are real, not invented


def test_every_zone_word_names_a_zone_a_blueprint_can_build():
    """A word that matched nothing would promise a zone nobody can build."""
    declared = {z.name for b in BLUEPRINTS for z in b.zones}
    invented = sorted(set(_ZONE_WORDS) - declared)
    assert invented == [], f"zone words with no blueprint zone: {invented}"


def test_zone_words_are_read_from_both_languages():
    assert set(named_zones("أنشئ شبكة موظفين وضيوف")) == {"users", "guest"}
    assert set(named_zones("network with staff and guests")) == {"users", "guest"}
    assert set(named_zones("شبكة خوادم وتطبيقات")) == {"app", "servers"}
    assert named_zones("أنشئ شبكة") == ()


def test_candidates_are_exactly_the_blueprints_that_contain_the_zones():
    """Derived from BLUEPRINTS, so a new blueprint cannot be missed."""
    for zones in (("users", "guest"), ("users", "voice"),
                  ("app", "servers"), ("users",), ()):
        wanted = set(zones)
        expected = {
            b.blueprint_id for b in BLUEPRINTS
            if wanted <= {z.name for z in b.zones}
        }
        assert set(candidate_blueprints(zones)) == expected
        # and every candidate really can build them
        for bid in candidate_blueprints(zones):
            blueprint = next(b for b in BLUEPRINTS if b.blueprint_id == bid)
            assert wanted <= {z.name for z in blueprint.zones}


def test_staff_plus_guests_offers_three_designs_not_a_default():
    """The honest answer to an underspecified request is a choice."""
    assert candidate_blueprints(("users", "guest")) == (
        "guest_office", "campus", "secure_office")


# ======================================= 3. labels round-trip


@pytest.mark.parametrize("blueprint_id", sorted({b.blueprint_id for b in BLUEPRINTS}))
def test_every_blueprint_id_names_itself(blueprint_id):
    """"طبق guest_office" was read as "office" and died at INTENT_ELICITATION."""
    for phrase in (f"apply {blueprint_id}", f"طبق {blueprint_id}"):
        verb, args = classify_intent(phrase)
        assert verb is IntentVerb.APPLY_INTENT, phrase
        assert args.get("network_type") == blueprint_id, phrase


def test_every_blueprint_id_is_in_the_parser_vocabulary():
    assert set(blueprint_ids()) <= set(_network_type_vocabulary())


def test_the_offered_actions_parse_back_to_a_runnable_apply():
    """Every action the operator offers must be one it can execute."""
    store, _kid, _collector, _ta = make_ledger_stack()
    op = ChatOperator(store=store, runner=None)
    reply = op._do_design_request({"network_type": None,
                                   "zones": ("users", "guest")}, "ar")
    assert reply.status is ReplyStatus.NEEDS_INPUT
    assert reply.actions, "a question with no options is not actionable"
    for action in reply.actions:
        verb, args = classify_intent(action["label"])
        assert verb is IntentVerb.APPLY_INTENT, action["label"]
        assert args.get("network_type") in blueprint_ids(), action["label"]


def test_an_unknown_type_is_refused_with_the_menu_not_passed_through():
    """"enterprise" is not a blueprint; inventing one would be a lie."""
    store, _kid, _collector, _ta = make_ledger_stack()
    op = ChatOperator(store=store, runner=None)
    reply = op._do_design("enterprise", "ar", apply=False)
    assert reply.status is ReplyStatus.NEEDS_INPUT
    assert set(reply.data["candidates"]) == set(blueprint_ids())
    assert reply.data["requested"] == "enterprise"


# ======================================= 4. the verdict tells the truth


@pytest.mark.parametrize("final,verdict,status,must_not_say_applied", [
    ("COMPLETE-APPLIED", "APPLIED", ReplyStatus.OK, False),
    ("INCOMPLETE-APPLIED", "APPLIED", ReplyStatus.FAILURE, True),
    ("INCOMPLETE-APPLIED", "INCOMPLETE", ReplyStatus.FAILURE, True),
    ("INCOMPLETE-APPLIED", "NOTHING_APPLIED", ReplyStatus.FAILURE, True),
    ("BLOCKED-APPLY", "REJECTED", ReplyStatus.BLOCKED, True),
    ("BLOCKED-ROLLED-BACK", "ROLLED_BACK", ReplyStatus.BLOCKED, True),
    ("BLOCKED-DESIGN", "UNKNOWN", ReplyStatus.BLOCKED, True),
    ("COMPLETE-PARTIAL", "PARTIAL", ReplyStatus.FAILURE, True),
    ("COMPLETE-STAGED", "STAGED", ReplyStatus.INFO, True),
])
def test_the_reply_never_claims_success_the_run_did_not_achieve(
        final, verdict, status, must_not_say_applied):
    store, _kid, _collector, _ta = make_ledger_stack()
    op = ChatOperator(store=store, runner=None)
    report = SimpleNamespace(
        final=final,
        execution={"outcome": verdict,
                   "change_records": [_change_record("seed-01", "APPLIED")]},
        verification={"tests_total": 19, "passed": ("a",) * 15, "failed": (),
                      "unrun": {"t": "why"}, "verdict": "INCOMPLETE"},
        renders={}, phases=[], execution_records=[],
    )
    reply = op._apply_verdict_reply(report, "ar")
    assert reply.status is status, final
    assert reply.data["final"] == final
    if must_not_say_applied:
        assert "تم التطبيق" not in reply.summary
        assert "applied and verified" not in reply.summary


def test_verification_counts_are_counts_not_test_id_lists():
    """``passed`` is a tuple of ids; printing it printed 15 test names."""
    store, _kid, _collector, _ta = make_ledger_stack()
    op = ChatOperator(store=store, runner=None)
    report = SimpleNamespace(
        final="INCOMPLETE-APPLIED",
        execution={"outcome": "APPLIED", "change_records": []},
        verification={"tests_total": 19, "passed": ("t",) * 15, "failed": (),
                      "unrun": {f"u{i}": "why" for i in range(4)},
                      "verdict": "INCOMPLETE"},
        renders={}, phases=[], execution_records=[],
    )
    detail = op._apply_verdict_reply(report, "en").detail
    assert "15/19 passed" in detail
    assert "4 unrun" in detail
    assert "CONNECTIVITY" not in detail


# ======================================= 5. end to end, real engine


class _SimRunner:
    """The same runner ``cli_main`` builds for --simulate."""

    def __init__(self, engine, fabric):
        self._engine = engine
        self._fabric = fabric

    def run(self, *, port, execute, answers):
        from netops_autopilot.cli import ScriptedIO
        self._engine.io = ScriptedIO(dict(answers))
        return self._engine.run(
            probe_port_session_factory=lambda p: self._fabric.probe(p),
            mgmt_session_factory=self._fabric, port=port, execute=execute)


def _live_operator():
    store, key_id, _collector, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=None, time_authority=time_auth)
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    return ChatOperator(store=store, runner=_SimRunner(engine, fabric))


def test_the_whole_request_runs_and_reports_what_the_engine_said():
    """From Arabic words to a real run, with the engine's own verdict.

    The simulated fabric's WAN zone takes its address from the provider, so
    four isolation tests cannot run and the engine grades INCOMPLETE. That is
    the state the reply must describe — the old code answered "applied".
    """
    op = _live_operator()
    assert op.handle("discover").status is ReplyStatus.OK

    ask = op.handle("أنشئ شبكة موظفين وضيوف")
    assert ask.status is ReplyStatus.NEEDS_INPUT
    assert set(ask.data["zones"]) == {"users", "guest"}

    apply_reply = op.handle(ask.actions[0]["label"])
    assert apply_reply.intent is IntentVerb.APPLY_INTENT
    assert apply_reply.data["final"] == op._ctx.last_run.final
    # The run really did put configuration on the devices...
    assert apply_reply.data["applied_devices"], apply_reply.data
    # ...and the reply says so without claiming the requirement was met.
    if apply_reply.data["final"] != "COMPLETE-APPLIED":
        assert apply_reply.status is not ReplyStatus.OK
        assert "تم التطبيق" not in apply_reply.summary
