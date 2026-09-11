"""Phase W — every scripted answer must reach the question it was written for.

This is a guard against the class of defect that broke the scripted runs twice:
adding a question to the orchestrator silently shifts every later answer one
slot, and ScriptedIO's "default to y / empty when the queue runs dry" hides it
instead of failing. The invariants checked here are behavioural, not structural:
nothing is consumed twice, nothing falls through to a default, and the answer a
question received is the one the script intended.
"""

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.cli.scenarios import SCENARIOS, make_scenario_io
from netops_autopilot.engines.blueprints import elicit
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _run_scenario(scenario_id):
    sc = SCENARIOS[scenario_id]
    io = make_scenario_io(scenario_id)
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=time_auth)
    report = engine.run(probe_port_session_factory=lambda port: fabric.probe(port),
                        mgmt_session_factory=fabric, port="SIM0", execute=False)
    return io, sc, report


def test_no_scripted_scenario_leaves_an_answer_unconsumed():
    for name, sc in SCENARIOS.items():
        io, sc, report = _run_scenario(name)
        assert not io._answers, (
            f"{name}: {io._answers} was never asked — the script has more answers "
            f"than the orchestrator has questions, so a question was removed")
        assert report.final.startswith("COMPLETE-"), (name, report.final)


def test_every_scenario_resolves_to_its_intended_blueprint():
    """The intent answer reached the intent question — not some earlier one."""
    for name, sc in SCENARIOS.items():
        _io, sc, report = _run_scenario(name)
        assert report.intent is not None and report.intent.status == "COMPILED", name
        expected = elicit(sc.blueprint_hint).blueprint.blueprint_id
        assert report.elicitation.blueprint.blueprint_id == expected, (
            f"{name}: blueprint={report.elicitation.blueprint.blueprint_id} "
            f"expected {expected} — answers are misaligned")


def test_the_dns_answer_reached_the_dns_question():
    """Only the DNS question can put a dns-server line inside a DHCP pool.

    A pool is emitted per internal zone, so every one of them must carry the
    same servers — and the comma the operator typed must have been normalised
    to the space-separated form IOS actually accepts.
    """
    _io, _sc, report = _run_scenario("branch")
    lines = report.renders["seed-01"].to_text().splitlines()
    pools = [l for l in lines if l.startswith("ip dhcp pool")]
    dns = [l for l in lines if l.startswith(" dns-server")]
    assert pools == ["ip dhcp pool users", "ip dhcp pool voice"]
    assert dns == [" dns-server 1.1.1.1 9.9.9.9"] * len(pools)
    assert not any("," in l for l in dns), "IOS rejects a comma-separated list"


def test_the_demo_command_acts_on_the_retry_answer(capsys):
    """A prompt whose answer is ignored is worse than no prompt at all.

    ``cli_main`` handed the engine ``fabric.open`` — a bound method, which does
    not carry the ``grant()`` hook the retry loop uses to model the operator
    supplying credentials. The demo therefore answered "y", printed nothing,
    and left ``access-sw1`` outside the managed set while still reporting
    success. This drives the real command entry point, not the engine, because
    the wiring is what was broken.
    """
    from netops_autopilot.cli_main import main

    rc = main(["demo", "--scenario", "branch"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ACCESS RETRY OK" in out, "the retry answer was accepted but not acted on"
    assert "ROLE access-sw1       L2_ACCESS" in out, out
    assert "UNMANAGED_NEIGHBOR" not in out
