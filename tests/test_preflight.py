"""E11 Preflight Engine: modeling assessment + Validation Fabric integration."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.adapters.interfaces import AdapterBase, CapabilityState
from netops_autopilot.adapters.registry import AdapterMatch, AdapterRegistry
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.engines.capability import CapabilityEngine
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.preflight import PreflightEngine
from netops_autopilot.engines.validation_fabric import (
    FabricVerdict, PolicyContext, StageStatus, ValidationFabric,
)
from netops_autopilot.ledger.models import Claim, SubjectEntity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.twin import DigitalTwin

NOW = datetime(2026, 9, 7, 9, 0, 0, tzinfo=timezone.utc)

FEATURE_DATA = {"matrix": {"test/os": {"version_constraint": ">=1.0", "features": {
    "vlan": {"discover": "YES", "configure": "YES", "validate": "YES", "rollback": "YES",
             "operational_test": "YES", "model_coverage": "YES", "basis": "lab_verified"},
}}}}
RECOVERY_DATA = {"matrix": {"test/os": {}}}
POLICY = PolicyContext(allowed_gate_classes=frozenset({"READ_ONLY", "LOW_RISK", "HIGH_RISK"}))


class ModeledAdapter(AdapterBase):
    """Claims exactly the operations enumerated; everything else UNKNOWN."""

    vendor_family = "test"

    def __init__(self, supported=()) -> None:
        self._supported = frozenset(supported)

    def capability(self, operation: str) -> CapabilityState:
        if operation in self._supported:
            return CapabilityState.SUPPORTED
        if operation.startswith("CREATE:never_supported"):
            return CapabilityState.NOT_SUPPORTED
        return CapabilityState.UNKNOWN


def claim(predicate, value, ref="dev-1"):
    return Claim(subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref=ref),
                 predicate=predicate, value=value, evidence_ids=["obs-1"],
                 verification_scope="DEVICE_IDENTITY", status="CONFIRMED",
                 relevance_check="PASS")


def twin_with(devices: dict[str, dict[str, object]]) -> DigitalTwin:
    store = LedgerStore(":memory:")
    twin = DigitalTwin(store, CounterCollector())
    for ref, fields in devices.items():
        for predicate, value in fields.items():
            twin.apply_claim(claim(predicate, value, ref), NOW)
    return twin


def node(node_id="n1", feature="vlan", target=("DEVICE", "dev-1"), vendor_os="test/os"):
    return IRNode(node_id=node_id, target=EntityRef(*target), operation=Operation.CREATE,
                  feature=feature, vendor_os=vendor_os, parameters={},
                  reversibility=Reversibility.REVERSIBLE_BY_REPLACE)


def engine(devices, supported=(), registrations=None) -> PreflightEngine:
    twin = twin_with(devices)
    registry = AdapterRegistry()
    if registrations is None and devices:
        for vendor_os in {f"{f.get('vendor')}/{f.get('os')}" for f in devices.values()}:
            vendor, _, os_name = vendor_os.partition("/")
            if vendor and vendor != "None" and os_name and os_name != "None":
                registry.register(AdapterMatch(vendor=vendor, os=os_name),
                                  lambda s=supported: ModeledAdapter(s))
    elif registrations:
        for match, factory in registrations:
            registry.register(match, factory)
    return PreflightEngine(registry, twin)


# ------------------------------------------------------------ per-node states
def test_fully_modeled_ir():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, supported=("CREATE:vlan",))
    status = eng.evaluate(ConfigIR(title="t", nodes=(node(),)))
    assert status.state == "SUPPORTED_AND_MODELED"
    assert "n1=MODELED:MODELED" in status.notes


def test_unknown_capability_is_partial_not_guessed():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}})  # no supported ops
    status = eng.evaluate(ConfigIR(title="t", nodes=(node(),)))
    assert status.state == "PARTIALLY_MODELED"
    assert "CAPABILITY_UNKNOWN" in status.notes


def test_no_adapter_is_not_modeled():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, registrations=[])
    status = eng.evaluate(ConfigIR(title="t", nodes=(node(),)))
    assert status.state == "NOT_MODELED"
    assert "NO_ADAPTER" in status.notes


def test_absent_entity_cannot_be_modeled():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}})
    ir = ConfigIR(title="t", nodes=(node(target=("DEVICE", "ghost")),))
    status = eng.evaluate(ir)
    assert status.state == "MODEL_INCOMPLETE"
    assert "ENTITY_ABSENT" in status.notes


def test_incomplete_identity_is_honest_gap():
    eng = engine({"dev-1": {"vendor": "test"}})  # no os evidenced
    status = eng.evaluate(ConfigIR(title="t", nodes=(node(),)))
    assert status.state == "MODEL_INCOMPLETE"
    assert "IDENTITY_INCOMPLETE" in status.notes


def test_vendor_os_mismatch_blocks_modeling():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}})
    ir = ConfigIR(title="t", nodes=(node(vendor_os="other/os"),))
    status = eng.evaluate(ir)
    assert status.state == "MODEL_INCOMPLETE"
    assert "VENDOR_OS_MISMATCH" in status.notes


def test_not_supported_capability_is_incomplete():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}})
    ir = ConfigIR(title="t", nodes=(node(feature="never_supported"),))
    status = eng.evaluate(ir)
    assert status.state == "MODEL_INCOMPLETE"
    assert "CAPABILITY_NOT_SUPPORTED" in status.notes


def test_not_modeled_dominates_the_aggregate():
    """L13: one unmodeled node poisons the aggregate — never rewritten.
    dev-2 declares a matching vendor_os but has no registered adapter."""
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, supported=("CREATE:vlan",))
    twin = eng._twin
    twin.apply_claim(claim("vendor", "other", "dev-2"), NOW)
    twin.apply_claim(claim("os", "os2", "dev-2"), NOW)
    ir = ConfigIR(title="t", nodes=(
        node(node_id="ok"),
        node(node_id="bad", target=("DEVICE", "dev-2"), vendor_os="other/os2"),
    ))
    status = eng.evaluate(ir)
    assert status.state == "NOT_MODELED"  # NO_ADAPTER for other/os2 dominates
    assert "bad=NOT_MODELED:NO_ADAPTER" in status.notes


def test_empty_input_cannot_claim_modeling():
    """ConfigIR itself rejects empty IR (IR_EMPTY); the aggregate must also
    fail closed if it were ever fed zero node states."""
    assert PreflightEngine._aggregate(()) == "NOT_MODELED"


def test_assessment_is_deterministic():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, supported=("CREATE:vlan",))
    ir = ConfigIR(title="t", nodes=(node(),))
    assert eng.evaluate(ir) == eng.evaluate(ir)
    assert eng.assess_nodes(ir) == eng.assess_nodes(ir)


# ------------------------------------------------------ fabric integration
def test_engine_plugs_into_fabric_preflight_stage():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, supported=("CREATE:vlan",))
    fabric = ValidationFabric(CapabilityEngine(FEATURE_DATA, RECOVERY_DATA), eng._twin,
                              preflight=eng.evaluate)
    result = fabric.run(ConfigIR(title="t", nodes=(node(),)), policy=POLICY,
                        device_versions={"dev-1": "1.0"})
    assert result.verdict is FabricVerdict.PASS
    assert result.preflight_status is StageStatus.PASS
    assert result.not_modeled_high_risk() is False


def test_unmodeled_high_risk_still_escalates_to_human():
    eng = engine({"dev-1": {"vendor": "test", "os": "os"}}, registrations=[])
    fabric = ValidationFabric(CapabilityEngine(FEATURE_DATA, RECOVERY_DATA), eng._twin,
                              preflight=eng.evaluate)
    mgmt_node = IRNode(node_id="n1", target=EntityRef("DEVICE", "dev-1"),
                       operation=Operation.CREATE, feature="ssh_mgmt", vendor_os="test/os",
                       parameters={}, reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                       touches_management_plane=True)
    result = fabric.run(ConfigIR(title="t", nodes=(mgmt_node,)), policy=POLICY,
                        device_versions={"dev-1": "1.0"})
    assert result.preflight_status is StageStatus.NOT_MODELED
    assert result.gate_class == "HIGH_RISK"
    assert result.not_modeled_high_risk() is True  # L06: human-only trigger
