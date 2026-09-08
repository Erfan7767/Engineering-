"""E09 Config IR: reversibility tags, gate derivation, structural rules."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.config_ir import (
    ConfigIR,
    DESTRUCTIVE_FEATURES,
    EntityRef,
    IRNode,
    Operation,
    Reversibility,
)


def node(node_id="n1", feature="vlan", reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
         target=("DEVICE", "dev-1"), operation=Operation.CREATE, parameters=None, **kw):
    return IRNode(
        node_id=node_id,
        target=EntityRef(*target),
        operation=operation,
        feature=feature,
        vendor_os="test/os",
        parameters=dict(parameters or {}),
        reversibility=reversibility,
        **kw,
    )


def test_valid_ir_builds():
    ir = ConfigIR(title="add vlan 100", nodes=(node(provides=("vlan:100",)),))
    assert ir.gate_class() == "LOW_RISK"
    assert ir.max_reversibility() is Reversibility.REVERSIBLE_BY_REPLACE
    assert not ir.contains_destructive()
    assert ir.node("n1").feature == "vlan"


def test_empty_ir_and_duplicate_ids_rejected():
    with pytest.raises(Failure):
        ConfigIR(title="x", nodes=())
    with pytest.raises(Failure) as exc:
        ConfigIR(title="x", nodes=(node(), node(node_id="n1")))
    assert "IR_DUPLICATE_NODE_ID" in exc.value.causes[0]


def test_empty_entity_ref_rejected():
    with pytest.raises(Failure):
        EntityRef("", "dev-1")


def test_irreversible_requires_justification_p0_18():
    bad = node(reversibility=Reversibility.IRREVERSIBLE)
    problems = bad.is_well_formed()
    assert any("irreversibility_reason" in p for p in problems)
    ok = node(reversibility=Reversibility.IRREVERSIBLE,
              parameters={"irreversibility_reason": "license activation is one-way on this platform"})
    assert ok.is_well_formed() == []


def test_dependency_token_shape_enforced():
    bad = node(provides=("vlan100",))  # missing class:name separator
    assert any("'class:name'" in p for p in bad.is_well_formed())


def test_gate_class_hierarchy_is_deterministic():
    # LOW_RISK baseline
    assert ConfigIR(title="t", nodes=(node(),)).gate_class() == "LOW_RISK"
    # management plane contact escalates
    mgmt = node(feature="ssh_mgmt", touches_management_plane=True)
    assert ConfigIR(title="t", nodes=(mgmt,)).gate_class() == "HIGH_RISK"
    # irreversible beats mgmt
    irr = node(node_id="n2", reversibility=Reversibility.IRREVERSIBLE,
               parameters={"irreversibility_reason": "r"}, touches_management_plane=True)
    assert ConfigIR(title="t", nodes=(mgmt, irr)).gate_class() == "IRREVERSIBLE"
    # destructive beats everything
    dest = node(node_id="n3", feature="factory_reset", parameters={"destructive": True})
    assert ConfigIR(title="t", nodes=(irr, dest)).gate_class() == "DESTRUCTIVE"
    assert dest.destructive
    assert "factory_reset" in DESTRUCTIVE_FEATURES


def test_max_reversibility_tracks_worst_node():
    ir = ConfigIR(title="t", nodes=(
        node(node_id="a"),
        node(node_id="b", reversibility=Reversibility.REVERSIBLE_MANUAL),
    ))
    assert ir.max_reversibility() is Reversibility.REVERSIBLE_MANUAL
