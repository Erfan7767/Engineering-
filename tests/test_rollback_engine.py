"""E16 Rollback Engine: FSM-3 driven with artifact-level honesty."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.rollback_engine import (
    RollbackArtifact,
    RollbackEngine,
    sha256_hex,
)
from netops_autopilot.fsm import rollback_fsm as rf
from netops_autopilot.ledger.store import LedgerStore

PLATFORM = "mikrotik/routeros"
TS = "2026-09-07T12:00:00+00:00"
CONTENT = b"/export\n/interface bridge add name=bridge-lan\n"


def node(node_id="n1", reversibility=Reversibility.REVERSIBLE_BY_REPLACE, parameters=None):
    return IRNode(node_id=node_id, target=EntityRef("DEVICE", "dev-1"),
                  operation=Operation.CREATE, feature="vlan", vendor_os="mikrotik/routeros",
                  parameters=dict(parameters or {}), reversibility=reversibility)


def artifact(mechanism="safe_mode", content=CONTENT, **over):
    fields = dict(mechanism=mechanism, content=content, recorded_hash=sha256_hex(content),
                  preserves_management_path=True, all_commands_reversible=True,
                  filesystem_prereqs_ok=True, recovery_path_verified=True, captured_at=TS)
    fields.update(over)
    return RollbackArtifact(**fields)


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    fsm = rf.build_rollback_fsm(recorder=store, counters=counters)
    engine = RollbackEngine(fsm, CapabilityEngine.load_builtin())
    return fsm, engine


# --------------------------------------------------------------------- plan
def test_plan_prefers_primary_mechanism_deterministically(rig):
    _, engine = rig
    ir = ConfigIR(title="t", nodes=(node("a"), node("b")))
    plan = engine.plan_from_ir(ir, PLATFORM)
    assert plan.feasible and plan.mechanism == "safe_mode"  # matrix note: PRIMARY
    assert "netinstall" not in plan.candidates  # destructive excluded (§9)
    assert "system_history" not in plan.candidates  # NOT_SUPPORTED by policy
    assert plan.node_sequence == ("b", "a")  # reverse application order
    assert engine.plan_from_ir(ir, PLATFORM) == plan


def test_plan_with_irreversible_nodes_is_infeasible(rig):
    _, engine = rig
    ir = ConfigIR(title="t", nodes=(
        node("a"),
        node("b", reversibility=Reversibility.IRREVERSIBLE,
             parameters={"irreversibility_reason": "one-way"}),
    ))
    plan = engine.plan_from_ir(ir, PLATFORM)
    assert plan.feasible is False
    assert plan.blockers == ("IRREVERSIBLE_NODES:b",)


def test_unknown_platform_has_no_candidates(rig):
    _, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), "ghost/os")
    assert plan.feasible is False
    assert "NO_SUPPORTED_MECHANISM" in plan.blockers


# ---------------------------------------------------------------- configure
def test_full_lifecycle_to_rollback_succeeded(rig):
    """Rollback path (D0-03 3.7): trigger from ARMED on verification FAIL."""
    fsm, engine = rig
    ir = ConfigIR(title="t", nodes=(node(),))
    plan = engine.plan_from_ir(ir, PLATFORM)
    art = artifact()
    engine.configure(plan, art)
    assert fsm.state == rf.READY  # all seven preconditions evidenced
    engine.arm("chg-1", "fsm2-arm-ev-1")
    assert fsm.state == rf.ARMED
    engine.trigger("chg-1", "verification FAIL on mandatory test", art)
    assert fsm.state == rf.ROLLBACK_TRIGGERED
    engine.complete("chg-1", reapplied=True, post_verify_pass=True, mgmt_reachable=True)
    assert fsm.state == rf.ROLLBACK_SUCCEEDED


def test_confirm_is_the_success_path_and_seals_the_change(rig):
    """D0-03 3.6: ARMED→CONFIRMED means apply succeeded (commit/release);
    a trigger after CONFIRMED is illegal — the FSM enforces it."""
    fsm, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    art = artifact()
    engine.configure(plan, art)
    engine.arm("chg-1", "ev-arm")
    engine.confirm("chg-1", "apply-ok-1", "window-1")
    assert fsm.state == rf.CONFIRMED
    with pytest.raises(Failure) as exc:
        engine.trigger("chg-1", "too late", art)
    assert "ILLEGAL_TRANSITION" in exc.value.causes[0]


def test_configure_recomputes_hash_and_refuses_mismatch(rig):
    fsm, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    tampered = artifact(recorded_hash="0" * 64)
    with pytest.raises(Failure) as exc:
        engine.configure(plan, tampered)
    assert "HASH_RECORDED" in exc.value.causes[0]
    assert fsm.state == rf.NOT_READY  # stopped before READY, after artifact:exists


def test_unmet_preconditions_are_listed_not_swallowed(rig):
    _, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    bad = artifact(preserves_management_path=False, recovery_path_verified=False)
    with pytest.raises(Failure) as exc:
        engine.configure(plan, bad)
    cause = exc.value.causes[0]
    assert "TARGET_PRESERVES_MANAGEMENT_PATH" in cause
    assert "RECOVERY_PATH_VERIFIED" in cause


def test_artifact_mechanism_must_match_plan(rig):
    _, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    with pytest.raises(Failure) as exc:
        engine.configure(plan, artifact(mechanism="binary_backup"))
    assert "ARTIFACT_MECHANISM_MISMATCH" in exc.value.causes[0]


def test_infeasible_plan_refuses_configure(rig):
    _, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(
        node("b", reversibility=Reversibility.IRREVERSIBLE,
             parameters={"irreversibility_reason": "x"}),)), PLATFORM)
    with pytest.raises(Failure) as exc:
        engine.configure(plan, artifact())
    assert "ROLLBACK_PLAN_INFEASIBLE" in exc.value.causes[0]


# ------------------------------------------------------- lifecycle honesty
def test_arm_requires_fsm2_binding(rig):
    fsm, engine = rig
    engine.configure(engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM), artifact())
    with pytest.raises(Failure) as exc:
        engine.arm("chg-1", "")
    assert "FSM2_ARM_BINDING_MISSING" in exc.value.causes[0]
    assert fsm.state == rf.READY


def test_trigger_rechecks_hash(rig):
    fsm, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    art = artifact()
    engine.configure(plan, art)
    engine.arm("chg-1", "ev-arm")
    engine.confirm("chg-1", "ev-ok", "ev-win")
    mutated = RollbackArtifact(mechanism=art.mechanism, content=art.content + b"x",
                               recorded_hash=art.recorded_hash,
                               preserves_management_path=True, all_commands_reversible=True,
                               filesystem_prereqs_ok=True, recovery_path_verified=True,
                               captured_at=TS)
    with pytest.raises(Failure) as exc:
        engine.trigger("chg-1", "reason", mutated)
    assert "ARTIFACT_HASH_MISMATCH" in exc.value.causes[0]
    assert fsm.state == rf.CONFIRMED  # no trigger without integrity
    with pytest.raises(Failure):
        engine.trigger("chg-1", "", art)


def test_failed_conjuncts_route_to_rollback_failed(rig):
    fsm, engine = rig
    plan = engine.plan_from_ir(ConfigIR(title="t", nodes=(node(),)), PLATFORM)
    art = artifact()
    engine.configure(plan, art)
    engine.arm("chg-1", "ev-arm")
    engine.trigger("chg-1", "mandatory test FAIL", art)
    engine.complete("chg-1", reapplied=True, post_verify_pass=False, mgmt_reachable=True)
    assert fsm.state == rf.ROLLBACK_FAILED  # success never claimed (L13)
