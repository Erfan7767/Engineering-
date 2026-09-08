"""E13 Blast Radius: propagation channels, risk class, honest gaps."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.engines.blast_radius import BlastRadiusEngine, RISK_ORDER
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.service_graph import ServiceGraph
from netops_autopilot.ledger.models import Claim, SubjectEntity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.twin import DigitalTwin

NOW = datetime(2026, 9, 7, 10, 0, 0, tzinfo=timezone.utc)


def node(node_id, feature="vlan", target=("DEVICE", "dev-1"), provides=(),
         requires=(), mgmt=False, reversibility=Reversibility.REVERSIBLE_BY_REPLACE):
    return IRNode(node_id=node_id, target=EntityRef(*target), operation=Operation.CREATE,
                  feature=feature, vendor_os="test/os", parameters={},
                  reversibility=reversibility, provides=provides, requires=requires,
                  touches_management_plane=mgmt)


@pytest.fixture(scope="module")
def graph():
    return ServiceGraph.load_builtin()


def twin_with_link() -> DigitalTwin:
    store = LedgerStore(":memory:")
    twin = DigitalTwin(store, CounterCollector())
    twin.apply_claim(Claim(
        subject_entity=SubjectEntity(entity_type="LINK", entity_ref="link-1"),
        predicate="link_state", value="DIRECT_NEIGHBOR_CONFIRMED",
        evidence_ids=["obs-1"], verification_scope="DIRECT_NEIGHBOR",
        status="CONFIRMED", relevance_check="PASS"), NOW)
    return twin


# ------------------------------------------------------------ direct + tokens
def test_direct_entities_sorted_and_unique(graph):
    ir = ConfigIR(title="t", nodes=(
        node("b", target=("DEVICE", "dev-2")), node("a"), node("c", target=("DEVICE", "dev-2")),
    ))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    assert [e.entity_ref for e in report.directly_affected] == ["dev-1", "dev-2"]


def test_token_and_entity_propagation_is_excluded_for_changed_nodes(graph):
    """All IR nodes are the change itself; propagation counts DOWNSTREAM
    effects, so internal_affected only grows when the IR models observers.
    Here everything is directly changed ⇒ no extra affected nodes."""
    ir = ConfigIR(title="t", nodes=(
        node("a", provides=("vlan:100",)), node("b", requires=("vlan:100",)),
    ))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    assert report.internal_affected_nodes == ()


def test_service_dependents_are_the_blast_downstream(graph):
    ir = ConfigIR(title="t", nodes=(node("dns_change", feature="dns"),))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    for dependent in ("radius", "tacacs", "syslog", "internet_egress", "dot1x"):
        assert dependent in report.affected_services
    assert report.affected_services == tuple(sorted(report.affected_services))


def test_unknown_feature_has_no_service_blast(graph):
    ir = ConfigIR(title="t", nodes=(node("x", feature="some_vlan_work"),))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    assert report.affected_services == ()


# ------------------------------------------------------------------ risk class
def test_risk_class_starts_from_gate_class(graph):
    ir = ConfigIR(title="t", nodes=(node("m", feature="ssh_mgmt"),))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    assert report.risk_class == "HIGH_RISK"  # mgmt feature ⇒ gate HIGH_RISK
    assert report.management_plane_touched is True


def test_destructive_is_never_downgraded(graph):
    ir = ConfigIR(title="t", nodes=(node("n", feature="netinstall"),))
    report = BlastRadiusEngine(service_graph=graph).evaluate(ir)
    assert report.risk_class == "DESTRUCTIVE"
    assert RISK_ORDER.index("DESTRUCTIVE") == len(RISK_ORDER) - 1


def test_blast_size_escalates_low_to_high(graph):
    """Absolute threshold (policy fact), never a percentage (T3)."""
    many = [node(f"n{i}", target=("DEVICE", f"dev-{i}")) for i in range(6)]
    ir = ConfigIR(title="t", nodes=tuple(many))
    report = BlastRadiusEngine(service_graph=graph, escalation_threshold=5).evaluate(ir)
    assert report.risk_class == "HIGH_RISK"
    small = ConfigIR(title="t", nodes=(node("one"),))
    assert BlastRadiusEngine(service_graph=graph, escalation_threshold=5).evaluate(small).risk_class == "LOW_RISK"


# ---------------------------------------------------------------- honest gaps
def test_link_without_endpoints_reports_gap(graph):
    report = BlastRadiusEngine(twin=twin_with_link(), service_graph=graph).evaluate(
        ConfigIR(title="t", nodes=(node("a"),)))
    assert "LINK_ENDPOINTS_NOT_MODELED" in report.gaps


def test_no_twin_no_gap_claim(graph):
    report = BlastRadiusEngine(twin=None, service_graph=graph).evaluate(
        ConfigIR(title="t", nodes=(node("a"),)))
    assert report.gaps == ()


def test_worst_case_is_deterministic_and_counts(graph):
    ir = ConfigIR(title="t", nodes=(node("a", feature="dns"),))
    eng = BlastRadiusEngine(service_graph=graph)
    r1, r2 = eng.evaluate(ir), eng.evaluate(ir)
    assert r1 == r2
    assert "blast touches 1 entit(y/ies)" in r1.worst_case
    assert "mgmt-plane not touched" in r1.worst_case
