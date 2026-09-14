"""The answers the operator gave must be the answers the engine receives.

The web surface constructed its engine with an ``OperatorIO`` that *invented*
the operator's answers. Asked "what kind of network", it returned ``"2"`` —
a hardcoded menu index — whatever the operator had typed; asked about the WAN
handoff, availability, growth or DNS servers, it returned strings it had made
up; and its ``confirm`` returned ``True`` unconditionally, so the BOND
human-decision gate was not a gate at all.

``ChatOperator._run_autopilot`` already computed the real answers from
``answer_script`` and published the requested intent on the operator, but the
engine-direct runner shape never received them: it reads answers from its own
``io``. So ``apply branch`` on the web applied the default blueprint instead.
Two symptoms of that are visible in the verification: the DHCP pools carried no
``dns-server`` (``T017:SERVICE_UP:dns``) and the zones belonged to a network
nobody had asked for.

Also fixed here: the runner shape was probed by catching ``TypeError``, so any
``TypeError`` raised *inside* a run was misread as "wrong shape" and the entire
change was executed a second time — against real devices, a second
configuration pass over hardware that had already been changed.
"""
from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from netops_autopilot.chat.operator import ChatOperator
from netops_autopilot.cli import RefusingIO, ScriptedIO
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.engines.blueprints import BLUEPRINTS
from netops_autopilot.engines.verification_executor import CLIENT_ZONE_KINDS
from netops_autopilot.web.server import create_app
from netops_autopilot.webui import WEBUI_DIR
from tests.support.simfabric import make_ledger_stack

REPO = pathlib.Path(__file__).resolve().parents[1]


def _client() -> TestClient:
    return TestClient(create_app(static_dir=WEBUI_DIR))


def _turn(client: TestClient, message: str) -> dict:
    with client.stream("GET", f"/chat/stream?message={message}&lang=en") as r:
        for line in r.iter_lines():
            if line and line.startswith("data:"):
                import json
                event = json.loads(line[len("data:"):].strip())
                if event.get("type") in ("reply", "error"):
                    return event
    raise AssertionError("the stream ended without a reply")


# ============================== 1. the named network is the one applied


@pytest.mark.parametrize("blueprint", BLUEPRINTS,
                         ids=[b.blueprint_id for b in BLUEPRINTS])
def test_the_blueprint_the_operator_named_is_the_one_built(blueprint):
    """``apply branch`` used to build the default blueprint on the web.

    The expected DHCP scope is derived from the blueprint's own zones, so this
    cannot drift from the data it is checking.
    """
    client = _client()
    assert _turn(client, "discover")["status"] == "OK"
    reply = _turn(client, f"apply%20{blueprint.blueprint_id}")
    verification = (reply.get("data") or {}).get("verification") or {}
    expected = sorted(z.name for z in blueprint.zones if z.kind in CLIENT_ZONE_KINDS)
    assert sorted(verification.get("dhcp_scope") or []) == expected, (
        f"{blueprint.blueprint_id}: the engine built a different network")


def test_the_dns_answer_reaches_the_pools():
    """``T017:SERVICE_UP:dns`` failed because the answer never arrived.

    ``dns_servers`` is a slot in ``ANSWER_SLOTS``; with the answers installed
    the pools carry a ``dns-server`` and the service test passes.
    """
    client = _client()
    _turn(client, "discover")
    reply = _turn(client, "apply%20guest_office")
    verification = (reply.get("data") or {}).get("verification") or {}
    # Asserted positively. "No dns test failed" passes vacuously when the run
    # never produced a verification at all, which is exactly what happens when
    # the answers do not reach the engine.
    assert verification.get("tests_total"), f"no verification ran: {reply.get('summary')}"
    dns_tests = [t for t in (verification.get("passed") or []) if "dns" in t]
    assert dns_tests, (
        f"the dns service test never passed: failed={verification.get('failed')} "
        f"unrun={list((verification.get('unrun') or {}).keys())} "
        f"reasons={verification.get('reasons')}")


# ============================== 2. an io with nobody behind it refuses


def test_a_channel_with_no_operator_refuses_to_answer():
    io = RefusingIO()
    with pytest.raises(Failure) as asked:
        io.ask("What kind of network do you want?")
    assert asked.value.cls is FailureClass.BLOCKED
    assert "NO_ANSWER_SOURCE" in asked.value.causes[0]


def test_the_bond_gate_is_not_a_yes_by_default():
    """``confirm`` returning True unconditionally is not a confirmation."""
    with pytest.raises(Failure):
        RefusingIO().confirm("Type BOND exactly to confirm")


def test_refusing_io_still_serves_output():
    """Refusing a decision is not refusing to report."""
    assert RefusingIO().show("phase output") is None


def test_the_web_engine_is_built_with_a_refusing_channel():
    """Not with something that answers on the operator's behalf."""
    operator = create_app._shared_chat_op if hasattr(
        create_app, "_shared_chat_op") else None
    client = _client()
    _turn(client, "discover")
    operator = create_app._shared_chat_op
    assert operator is not None
    with pytest.raises(Failure):
        operator._runner.io.ask("What kind of network do you want?")


# ============================== 3. no answer is invented in the product


def test_no_shipped_io_returns_an_invented_answer():
    """The defect was a ``return "2"`` where an operator's choice belonged.

    Checked as behaviour rather than by grepping for a class name: every
    OperatorIO shipped in the package must either consume answers it was given
    or refuse.
    """
    from netops_autopilot.cli.io import ConsoleIO, RefusingIO as _R, ScriptedIO as _S

    # ScriptedIO consumes what it was given and runs out honestly.
    scripted = _S(["branch"])
    assert scripted.ask("what kind of network?") == "branch"
    assert scripted.ask("what kind of network?") == ""

    # RefusingIO never answers.
    with pytest.raises(Failure):
        _R().ask("what kind of network?")

    # ConsoleIO reads a human; with stdin closed it yields no answer rather
    # than an invented one.
    import io as _io, sys
    saved = sys.stdin
    sys.stdin = _io.StringIO("")
    try:
        assert ConsoleIO().ask("what kind of network?") == ""
        assert ConsoleIO().confirm("BOND?") is False
    finally:
        sys.stdin = saved


def test_the_answer_inventing_io_is_gone_from_the_server():
    source = (REPO / "src" / "netops_autopilot" / "web" / "server.py").read_text(
        encoding="utf-8")
    assert "_NullIO" not in source
    assert 'return "2"' not in source


# ============================== 4. a failed run is never run twice


class _ExplodingRunner:
    """A runner whose run raises TypeError from *inside* the work."""

    def __init__(self):
        self.calls = 0
        self.io = None

    def run(self, *, probe_port_session_factory, mgmt_session_factory,
            port, execute):
        self.calls += 1
        raise TypeError("a genuine bug inside the run, not a signature problem")


class _AnswersRunner:
    def __init__(self):
        self.calls = 0
        self.seen = None

    def run(self, *, port, execute, answers):
        self.calls += 1
        self.seen = dict(answers)
        return "ran"


def _operator_with(runner):
    store, _kid, _collector, _ta = make_ledger_stack()
    return ChatOperator(store=store, runner=runner)


def test_a_typeerror_inside_a_run_does_not_trigger_a_second_run():
    """Against real devices a retry is a second configuration pass."""
    runner = _ExplodingRunner()
    operator = _operator_with(runner)
    with pytest.raises(TypeError):
        operator._run_autopilot(execute=True, intent="branch", apply_bond=True)
    assert runner.calls == 1, "the change was executed more than once"


def test_the_runner_shape_is_read_from_its_signature():
    assert _operator_with(_AnswersRunner())._runner_takes_answers() is True
    assert _operator_with(_ExplodingRunner())._runner_takes_answers() is False


def test_the_answers_are_handed_to_a_runner_that_accepts_them():
    runner = _AnswersRunner()
    operator = _operator_with(runner)
    assert operator._run_autopilot(execute=False, intent="campus") == "ran"
    assert runner.seen["intent"] == "campus"


# ============================== 5. streaming survives the run


def test_the_phase_stream_is_not_cut_off_by_installing_answers():
    """The answers go *inside* the streaming wrapper, not over it."""
    client = _client()
    seen = []
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        for line in r.iter_lines():
            if line and line.startswith("data:"):
                import json
                seen.append(json.loads(line[len("data:"):].strip()))
    kinds = {e.get("type") for e in seen}
    assert "show" in kinds, f"no phase output was streamed: {kinds}"
    assert "reply" in kinds
