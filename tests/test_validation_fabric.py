"""E10 Validation Fabric: nine stages, verdict algebra, L13/T2/T3 behavior."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.ledger.models import Claim, SubjectEntity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.twin import DigitalTwin
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.validation_fabric import (
    FabricVerdict,
    PolicyContext,
    PreflightStatus,
    StageStatus,
    ValidationFabric,
)

NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)

#: Test-only capability data where configure is lab-confirmed; the shipped
#: matrix stays UNKNOWN until sponsor-lab evidence (OI-0140).
FEATURE_DATA = {"matrix": {"test/os": {"version_constraint": ">=1.0", "features": {
    "vlan":       {"discover": "YES", "configure": "YES", "validate": "YES", "rollback": "YES",
                   "operational_test": "YES", "model_coverage": "YES", "basis": "lab_verified"},
    "ssh_mgmt":   {"discover": "YES", "configure": "YES", "validate": "YES", "rollback": "YES",
                   "operational_test": "YES", "model_coverage": "YES", "basis": "lab_verified"},
    "svi":        {"discover": "YES", "configure": "YES", "validate": "YES", "rollback": "YES",
                   "operational_test": "YES", "model_coverage": "YES", "basis": "lab_verified"},
    "static_route": {"discover": "YES", "configure": "PARTIAL", "validate": "YES", "rollback": "YES",
                     "operational_test": "YES", "model_coverage": "PARTIAL", "basis": "lab_verified"},
}}}}
RECOVERY_DATA = {"matrix": {"test/os": {}}}

POLICY = PolicyContext(allowed_gate_classes=frozenset({"READ_ONLY", "LOW_RISK", "HIGH_RISK"}))


def node(node_id="n1", feature="vlan", target=("DEVICE", "dev-1"),
         reversibility=Reversibility.REVERSIBLE_BY_REPLACE, parameters=None, **kw):
    return IRNode(node_id=node_id, target=EntityRef(*target), operation=Operation.CREATE,
                  feature=feature, vendor_os="test/os", parameters=dict(parameters or {}),
                  reversibility=reversibility, **kw)


@pytest.fixture()
def rig():
    capability = CapabilityEngine(FEATURE_DATA, RECOVERY_DATA)
    store = LedgerStore(":memory:")
    twin = DigitalTwin(store, CounterCollector())
    twin.apply_claim(Claim(
        subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
        predicate="vendor", value="test", evidence_ids=["obs-1"],
        verification_scope="DEVICE_IDENTITY", status="CONFIRMED", relevance_check="PASS",
    ), NOW)
    return ValidationFabric(capability, twin), twin


def test_happy_path_passes_all_stages(rig):
    fabric, _ = rig
    ir = ConfigIR(title="add vlan 100", nodes=(node(parameters={"vlan_id": 100}, provides=("vlan:100",)),))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.PASS
    assert [s.stage for s in result.stage_results] == list(__import__(
        "netops_autopilot.engines.validation_fabric", fromlist=["STAGES"]).STAGES)
    assert result.gate_class == "LOW_RISK"
    # L13: preflight recorded NOT_MODELED — PASS verdict does not rewrite it.
    assert result.preflight_status is StageStatus.NOT_MODELED
    assert result.not_modeled_high_risk() is False  # LOW_RISK ⇒ not human-only


def test_entity_guard_blocks_unknown_targets(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(target=("DEVICE", "ghost-device")),))
    result = fabric.run(ir, policy=POLICY, device_versions={"ghost-device": "1.0"})
    assert result.verdict is FabricVerdict.FAIL
    codes = {f.code for f in result.errors()}
    assert "ENTITY_NOT_IN_INVENTORY" in codes


def test_ipam_stage_catches_overlaps_and_bad_gateways(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(
        node(node_id="a", feature="svi", parameters={"subnet": "10.5.0.0/24", "gateway": "10.5.0.1"}),
        node(node_id="b", feature="svi", parameters={"subnet": "10.5.0.128/25", "gateway": "10.5.0.129"}),
    ))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.FAIL
    assert any(f.code == "IPAM_OVERLAP" for f in result.errors())

    ir2 = ConfigIR(title="t", nodes=(
        node(feature="svi", parameters={"subnet": "10.5.0.0/24", "gateway": "192.168.9.9"}),))
    result2 = fabric.run(ir2, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert result2.verdict is FabricVerdict.FAIL
    assert any(f.code == "ADDRESS_OUTSIDE_SUBNET" for f in result2.errors())


def test_dependency_stage_requires_provides_and_cycles(rig):
    fabric, _ = rig
    # unsatisfied requires
    ir = ConfigIR(title="t", nodes=(node(requires=("vlan:77",)),))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "UNSATISFIED_REQUIRES" for f in result.errors())
    # satisfied via external provision
    result_ok = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"},
                           external_provides=frozenset({"vlan:77"}))
    assert not any(f.code == "UNSATISFIED_REQUIRES" for f in result_ok.errors())
    # cycle: a requires b's token, b depends_on a
    ir_cycle = ConfigIR(title="t", nodes=(
        node(node_id="a", requires=("token:x",)),
        node(node_id="b", provides=("token:x",), depends_on=("a",)),
    ))
    result_cycle = fabric.run(ir_cycle, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "DEPENDENCY_CYCLE" for f in result_cycle.errors())
    # duplicate provides
    ir_dup = ConfigIR(title="t", nodes=(
        node(node_id="a", provides=("token:x",)),
        node(node_id="b", provides=("token:x",)),
    ))
    result_dup = fabric.run(ir_dup, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "DUPLICATE_PROVIDES" for f in result_dup.errors())


def test_missing_policy_context_is_blocked_not_passed(rig):
    """T3: authority cannot be judged without policy ⇒ BLOCKED."""
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(),))
    result = fabric.run(ir, policy=None, device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.BLOCKED
    assert result.stage("POLICY").status is StageStatus.BLOCKED


def test_policy_gate_allow_set_enforced(rig):
    fabric, _ = rig
    mgmt = node(feature="ssh_mgmt", touches_management_plane=True, parameters={"vlan_id": None})
    ir = ConfigIR(title="t", nodes=(mgmt,))
    strict = PolicyContext(allowed_gate_classes=frozenset({"READ_ONLY", "LOW_RISK"}))
    result = fabric.run(ir, policy=strict, device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.FAIL
    assert any(f.code == "POLICY_GATE_NOT_ALLOWED" for f in result.errors())


def test_mgmt_feature_must_be_flagged_l15(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(feature="ssh_mgmt"),))  # unflagged
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "MGMT_FEATURE_NOT_FLAGGED" for f in result.errors())


def test_capability_unknown_blocks_even_with_everything_else(rig):
    """T2/L13: UNKNOWN configure capability ⇒ not planned, full stop."""
    builtin = CapabilityEngine.load_builtin()  # shipped seed: configure=UNKNOWN
    store = LedgerStore(":memory:")
    twin = DigitalTwin(store, CounterCollector())
    twin.apply_claim(Claim(
        subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
        predicate="vendor", value="cisco", evidence_ids=["obs-1"],
        verification_scope="DEVICE_IDENTITY", status="CONFIRMED", relevance_check="PASS",
    ), NOW)
    fabric = ValidationFabric(builtin, twin)
    real = IRNode(node_id="n1", target=EntityRef("DEVICE", "dev-1"), operation=Operation.CREATE,
                  feature="vlan", vendor_os="cisco/ios-xe", parameters={"vlan_id": 10},
                  reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
    ir = ConfigIR(title="t", nodes=(real,))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "17.9.4a"})
    assert result.verdict is FabricVerdict.FAIL
    assert any(f.code == "CAPABILITY_NOT_CONFIRMED" for f in result.errors())


def test_missing_device_version_is_blocked_typed(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(),))
    result = fabric.run(ir, policy=POLICY, device_versions={})
    assert result.verdict is FabricVerdict.BLOCKED
    assert any(f.code == "BLOCKED_DEVICE_VERSION_UNKNOWN" for f in result.errors())


def test_partial_capability_warns_but_passes(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(feature="static_route"),))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.PASS
    warnings = [f for r in result.stage_results for f in r.findings if f.code == "CAPABILITY_PARTIAL"]
    assert warnings


def test_invalid_vlan_id_caught_semantic(rig):
    fabric, _ = rig
    ir = ConfigIR(title="t", nodes=(node(parameters={"vlan_id": 5000}),))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "INVALID_VLAN_ID" for f in result.errors())


def test_irreversible_ir_triggers_human_gate_warning_and_escalation(rig):
    fabric, _ = rig
    irr = node(reversibility=Reversibility.IRREVERSIBLE,
               parameters={"irreversibility_reason": "license bind is one-way"})
    ir = ConfigIR(title="t", nodes=(irr,))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert result.gate_class == "IRREVERSIBLE"
    assert any(f.code == "HUMAN_GATE_REQUIRED" for r in result.stage_results for f in r.findings)
    # NOT_MODELED preflight + HIGH_RISK-or-above ⇒ HUMAN_ONLY trigger (L06).
    assert result.not_modeled_high_risk() is True


def test_injected_preflight_modes_change_the_preflight_stage(rig):
    capability = CapabilityEngine(FEATURE_DATA, RECOVERY_DATA)
    store = LedgerStore(":memory:")
    twin = DigitalTwin(store, CounterCollector())
    twin.apply_claim(Claim(
        subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref="dev-1"),
        predicate="vendor", value="test", evidence_ids=["obs-1"],
        verification_scope="DEVICE_IDENTITY", status="CONFIRMED", relevance_check="PASS",
    ), NOW)
    ir = ConfigIR(title="t", nodes=(node(),))

    modeled = ValidationFabric(capability, twin, preflight=lambda _ir: PreflightStatus("SUPPORTED_AND_MODELED", "ok"))
    assert modeled.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"}).preflight_status is StageStatus.PASS

    failed = ValidationFabric(capability, twin, preflight=lambda _ir: PreflightStatus("PARSE_FAILED", "config unparsable"))
    assert failed.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"}).verdict is FabricVerdict.FAIL


def test_unknown_vendor_os_caught_by_lint(rig):
    fabric, _ = rig
    weird = IRNode(node_id="n1", target=EntityRef("DEVICE", "dev-1"), operation=Operation.CREATE,
                   feature="vlan", vendor_os="vendor/none", parameters={"vlan_id": 10},
                   reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
    ir = ConfigIR(title="t", nodes=(weird,))
    result = fabric.run(ir, policy=POLICY, device_versions={"dev-1": "1.0"})
    assert any(f.code == "UNKNOWN_VENDOR_OS" for f in result.errors())
