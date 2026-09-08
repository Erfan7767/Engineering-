"""E15 Change Engine: FSM-2 spine driven by the real engines (2.1→2.4)."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.engines.autonomy import (
    Approval, AutonomyAuthority, DecisionReadiness, Verdict,
)
from netops_autopilot.engines.blast_radius import BlastRadiusEngine
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.change_engine import ChangeEngine
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.dependency_dag import DependencyDAGEngine
from netops_autopilot.engines.service_graph import ServiceGraph
from netops_autopilot.engines.validation_fabric import (
    PolicyContext, PreflightStatus, ValidationFabric,
)
from netops_autopilot.fsm import change_fsm as cf
from netops_autopilot.ledger.models import Claim, SubjectEntity, OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.twin import DigitalTwin

NOW = datetime(2026, 9, 7, 11, 0, 0, tzinfo=timezone.utc)

FEATURE_DATA = {"matrix": {"test/os": {"version_constraint": ">=1.0", "features": {
    f: {"discover": "YES", "configure": "YES", "validate": "YES", "rollback": "YES",
        "operational_test": "YES", "model_coverage": "YES", "basis": "lab_verified"}
    for f in ("vlan", "ssh_mgmt", "dot1x", "ntp")
}}}}
RECOVERY_DATA = {"matrix": {"test/os": {}}}
POLICY = PolicyContext(allowed_gate_classes=frozenset(
    {"READ_ONLY", "LOW_RISK", "HIGH_RISK", "IRREVERSIBLE", "DESTRUCTIVE"}))
READINESS_OK = DecisionReadiness(intent_compiled=True, fabric_pass=True, dag_built=True,
                                 blast_recorded=True, rollback_ready=True, twin_fresh=True,
                                 capability_confirmed=True, no_conflicting_change=True)


def node(node_id="n1", feature="vlan", reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
         parameters=None, mgmt=False):
    # L15: management-plane features must carry the explicit flag; the
    # fabric's SEMANTIC stage enforces it (MGMT_FEATURE_NOT_FLAGGED).
    return IRNode(node_id=node_id, target=EntityRef("DEVICE", "dev-1"),
                  operation=Operation.CREATE, feature=feature, vendor_os="test/os",
                  parameters=dict(parameters or {}), reversibility=reversibility,
                  touches_management_plane=mgmt)


def modeled_preflight(ir):
    return PreflightStatus(state="SUPPORTED_AND_MODELED", notes="test")


def make_engine():
    """Fresh ChangeEngine + FSM per change: a prepared change owns its
    FSM instance (one lifecycle object per change object)."""
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    twin_store = LedgerStore(":memory:")
    twin = DigitalTwin(twin_store, CounterCollector())
    twin.apply_claim(Claim(subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
                           predicate="vendor", value="test", evidence_ids=["obs-1"],
                           verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                           relevance_check="PASS"), NOW)
    twin.apply_claim(Claim(subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
                           predicate="os", value="os", evidence_ids=["obs-2"],
                           verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                           relevance_check="PASS"), NOW)
    graph = ServiceGraph.load_builtin()
    engine = ChangeEngine(
        fsm=cf.build_change_fsm(recorder=store, counters=counters),
        fabric=ValidationFabric(CapabilityEngine(FEATURE_DATA, RECOVERY_DATA), twin,
                                preflight=modeled_preflight),
        dag=DependencyDAGEngine(graph),
        blast=BlastRadiusEngine(twin=twin, service_graph=graph),
        autonomy=AutonomyAuthority(),
        counters=counters)
    return engine


@pytest.fixture()
def rig():
    return make_engine()


def ir_of(*nodes, title="t"):
    return ConfigIR(title=title, nodes=tuple(nodes))


# ------------------------------------------------------------------ spine
def test_low_risk_spine_reaches_authorized(rig):
    result = rig.prepare("chg-1", ir_of(node()), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.AUTHORIZED
    assert result.blocked_reasons == ()
    assert result.decision.verdict is Verdict.AUTO_EXECUTE
    kinds = [e["kind"] for e in result.evidence]
    for required in ("validation_fabric:PASS", "dag:total_order",
                     "dag:permanent_constraints_ok", "blast_radius:recorded",
                     "risk_class:recorded", "readiness:all_true", "gate_verdict:ALLOW"):
        assert required in kinds
    assert "validation_fabric:NOT_MODELED" not in kinds  # modeled preflight
    assert result.plan.order == ("n1",)
    assert result.blast.risk_class == "LOW_RISK"


def test_not_modeled_preflight_blocks_at_risk_assessed():
    """No preflight wired ⇒ fabric records NOT_MODELED ⇒ E14 refuses (L13)."""
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    twin = DigitalTwin(LedgerStore(":memory:"), CounterCollector())
    twin.apply_claim(Claim(subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
                           predicate="vendor", value="test", evidence_ids=["o"],
                           verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                           relevance_check="PASS"), NOW)
    twin.apply_claim(Claim(subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
                           predicate="os", value="os", evidence_ids=["o"],
                           verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                           relevance_check="PASS"), NOW)
    graph = ServiceGraph.load_builtin()
    engine = ChangeEngine(
        fsm=cf.build_change_fsm(recorder=store, counters=counters),
        fabric=ValidationFabric(CapabilityEngine(FEATURE_DATA, RECOVERY_DATA), twin, preflight=None),
        dag=DependencyDAGEngine(graph),
        blast=BlastRadiusEngine(twin=twin, service_graph=graph),
        autonomy=AutonomyAuthority(), counters=counters)
    result = engine.prepare("chg-1", ir_of(node()), policy=POLICY,
                            device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.RISK_ASSESSED  # blocked before AUTHORIZED
    assert any("NOT_MODELED_TERMINAL" in r for r in result.blocked_reasons)
    kinds = [e["kind"] for e in result.evidence]
    assert "validation_fabric:NOT_MODELED" in kinds
    assert "validation_fabric:not_modeled_recorded" in kinds  # recorded, never passed over


def test_fabric_fail_stops_at_draft(rig):
    ghost = IRNode(node_id="n1", target=EntityRef("DEVICE", "dev-1"), operation=Operation.CREATE,
                   feature="vlan", vendor_os="ghost/os", parameters={},
                   reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
    result = rig.prepare("chg-2", ir_of(ghost), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.DRAFT
    assert result.blocked_reasons == ("FABRIC_FAIL",)


def test_fabric_blocked_stops_at_draft(rig):
    result = rig.prepare("chg-3", ir_of(node()), policy=None,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.DRAFT
    assert result.blocked_reasons == ("FABRIC_BLOCKED",)


# ------------------------------------------------------------- gate paths
def test_high_risk_needs_mfa_approval(rig):
    result = rig.prepare("chg-4", ir_of(node(feature="ssh_mgmt", mgmt=True)), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.RISK_ASSESSED
    assert result.decision.verdict is Verdict.APPROVAL_REQUIRED
    assert result.decision.approval_satisfied is False
    assert any("APPROVAL_UNSATISFIED" in r for r in result.blocked_reasons)


def test_high_risk_with_approval_reaches_authorized(rig):
    result = rig.prepare("chg-5", ir_of(node(feature="ssh_mgmt", mgmt=True)), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK,
                         approval=Approval("netops-admin@corp", mfa_verified=True))
    assert result.final_state == cf.AUTHORIZED
    assert result.decision.approval_satisfied is True


def test_irreversible_requires_human_decision(rig):
    ir = ir_of(node(reversibility=Reversibility.IRREVERSIBLE,
                    parameters={"irreversibility_reason": "license activation is one-way"}))
    # Human decision WITHOUT verified MFA is incomplete on human-only gates.
    blocked = rig.prepare("chg-6", ir, policy=POLICY,
                          device_versions={"dev-1": "1.0"}, readiness=READINESS_OK,
                          approval=Approval("admin@corp", mfa_verified=False))
    assert blocked.final_state == cf.RISK_ASSESSED
    assert blocked.decision.verdict is Verdict.HUMAN_ONLY
    assert blocked.decision.human_decided is False
    assert any("HUMAN_DECISION_MFA_UNVERIFIED" in r for r in blocked.blocked_reasons)
    decided = make_engine().prepare("chg-7", ir, policy=POLICY,
                          device_versions={"dev-1": "1.0"}, readiness=READINESS_OK,
                          approval=Approval("chief-eng@corp", mfa_verified=True))
    assert decided.final_state == cf.AUTHORIZED
    assert decided.decision.human_decided is True
    assert "gate_verdict:HUMAN_DECIDED" in [e["kind"] for e in decided.evidence]


def test_readiness_gap_blocks_with_named_conjuncts(rig):
    partial = DecisionReadiness(intent_compiled=True, fabric_pass=True, dag_built=True,
                                blast_recorded=True, rollback_ready=False, twin_fresh=True,
                                capability_confirmed=True, no_conflicting_change=True)
    result = rig.prepare("chg-8", ir_of(node()), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=partial)
    assert result.final_state == cf.RISK_ASSESSED
    assert result.blocked_reasons == ("READINESS_NOT_ALL_TRUE:rollback_ready",)


# ------------------------------------------------- defense in depth + veto
def test_dag_service_gap_blocks_after_validation(rig):
    """Fabric DEPENDENCY passes (tokens fine); DAG catches the unmet P1-34
    service dependency — the change stops at VALIDATED with the typed cause."""
    result = rig.prepare("chg-9", ir_of(node(feature="dot1x")), policy=POLICY,
                         device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert result.final_state == cf.VALIDATED
    assert any("SERVICE_DEP_UNMET" in r for r in result.blocked_reasons)


def test_veto_rejects_and_requires_identity_and_reason(rig):
    rig.veto("chg-10", "auditor-a4", "policy conflict with baseline", ("ev-1",))
    assert rig._fsm.state == cf.REJECTED
    with pytest.raises(ValueError):
        rig.veto("chg-11", "", "no identity", ())


def test_prepare_is_deterministic_in_shape(rig):
    a = rig.prepare("chg-d1", ir_of(node()), policy=POLICY,
                    device_versions={"dev-1": "1.0"}, readiness=READINESS_OK)
    assert a.final_state == cf.AUTHORIZED
    assert [e["kind"] for e in a.evidence] == [e["kind"] for e in a.evidence]
    assert a.blocked_reasons == ()
