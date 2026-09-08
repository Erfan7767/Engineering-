"""E12 Dependency DAG: total order, permanent constraints (FSM-2 2.2)."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.config_ir import ConfigIR, EntityRef, IRNode, Operation, Reversibility
from netops_autopilot.engines.dependency_dag import DependencyDAGEngine
from netops_autopilot.engines.service_graph import ServiceGraph


def node(node_id, feature="vlan", provides=(), requires=(), depends_on=(),
         conflicts=(), blocks=(), mgmt=False):
    return IRNode(node_id=node_id, target=EntityRef("DEVICE", "dev-1"),
                  operation=Operation.CREATE, feature=feature, vendor_os="test/os",
                  parameters={}, reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
                  provides=provides, requires=requires, depends_on=depends_on,
                  conflicts=conflicts, blocks=blocks, touches_management_plane=mgmt)


@pytest.fixture(scope="module")
def engine():
    return DependencyDAGEngine(ServiceGraph.load_builtin())


# -------------------------------------------------------------- total order
def test_depends_on_chain_orders_totally(engine):
    ir = ConfigIR(title="t", nodes=(node("c", depends_on=("b",)), node("a"), node("b", depends_on=("a",))))
    plan = engine.build(ir)
    assert plan.order == ("a", "b", "c")
    assert sorted(plan.order) == ["a", "b", "c"]  # total: every node once


def test_requires_provides_orders_provider_first(engine):
    ir = ConfigIR(title="t", nodes=(
        node("user", requires=("vlan:100",)),
        node("maker", provides=("vlan:100",)),
    ))
    plan = engine.build(ir)
    assert plan.order.index("maker") < plan.order.index("user")
    assert any(e.reason == "REQUIRES_TOKEN:vlan:100" for e in plan.edges)


def test_plan_is_deterministic(engine):
    ir = ConfigIR(title="t", nodes=(node("z"), node("a", provides=("x",)), node("m", requires=("x",))))
    assert engine.build(ir) == engine.build(ir)


def test_cycle_is_typed_failure(engine):
    ir = ConfigIR(title="t", nodes=(node("a", depends_on=("b",)), node("b", depends_on=("a",))))
    with pytest.raises(Failure) as exc:
        engine.build(ir)
    assert "DEPENDENCY_CYCLE" in exc.value.causes[0]
    assert "['a', 'b']" in exc.value.causes[0]


def test_unknown_depends_on_fails_fast(engine):
    ir = ConfigIR(title="t", nodes=(node("a", depends_on=("ghost",)),))
    with pytest.raises(Failure) as exc:
        engine.build(ir)
    assert "UNKNOWN_DEPENDS_ON" in exc.value.causes[0]


def test_unsatisfied_requires_fails_unless_external(engine):
    ir = ConfigIR(title="t", nodes=(node("a", requires=("vlan:42",)),))
    with pytest.raises(Failure) as exc:
        engine.build(ir)
    assert "UNSATISFIED_REQUIRES" in exc.value.causes[0]
    plan = engine.build(ir, external_provides=frozenset({"vlan:42"}))
    assert plan.order == ("a",)


def test_duplicate_provides_fails_fast(engine):
    ir = ConfigIR(title="t", nodes=(
        node("a", provides=("dup",)), node("b", provides=("dup",)),
    ))
    with pytest.raises(Failure) as exc:
        engine.build(ir)
    assert "DUPLICATE_PROVIDES" in exc.value.causes[0]


def test_conflicts_and_blocks_reject_cohabitation(engine):
    with pytest.raises(Failure) as exc:
        engine.build(ConfigIR(title="t", nodes=(
            node("a", conflicts=("x",)), node("b", provides=("x",)))))
    assert "CONFLICT" in exc.value.causes[0]
    with pytest.raises(Failure) as exc:
        engine.build(ConfigIR(title="t", nodes=(
            node("a", blocks=("y",)), node("b", provides=("y",)))))
    assert "BLOCKS_VIOLATION" in exc.value.causes[0]


# --------------------------------------------- guard 2.2 permanent constraints
def test_mgmt_plane_orders_first_among_ready(engine):
    ir = ConfigIR(title="t", nodes=(node("aaa_change"), node("zz_mgmt", mgmt=True)))
    plan = engine.build(ir)
    assert plan.order[0] == "zz_mgmt"  # mgmt first even though 'z' > 'a'
    assert plan.mgmt_first_applied is True


def test_service_dependencies_order_aaa_ntp_pki_before_dependents(engine):
    """Permanent constraint: services declared in P1-34 order their users."""
    ir = ConfigIR(title="t", nodes=(
        node("dot1x_apply", feature="dot1x"),
        node("ntp_up", feature="ntp", provides=("service:ntp",)),
        node("dns_up", feature="dns", provides=("service:dns",)),
        node("radius_up", feature="radius", provides=("service:radius",)),
    ))
    plan = engine.build(ir)
    pos = {nid: i for i, nid in enumerate(plan.order)}
    assert pos["ntp_up"] < pos["radius_up"]
    assert pos["dns_up"] < pos["radius_up"]
    assert pos["radius_up"] < pos["dot1x_apply"]
    assert any(e.reason == "SERVICE_DEP:radius" for e in plan.edges)


def test_unmet_service_dependency_is_typed(engine):
    ir = ConfigIR(title="t", nodes=(node("r", feature="radius"),))
    with pytest.raises(Failure) as exc:
        engine.build(ir)
    assert "SERVICE_DEP_UNMET" in exc.value.causes[0]
    # external satisfaction via the service: token namespace
    plan = engine.build(ir, external_provides=frozenset({"service:dns", "service:ntp"}))
    assert plan.order == ("r",)


def test_edges_are_deduplicated_and_sorted(engine):
    ir = ConfigIR(title="t", nodes=(
        node("a", provides=("x",)),
        node("b", requires=("x",), depends_on=("a",)),  # two reasons, one pair
    ))
    plan = engine.build(ir)
    pairs = [(e.src, e.dst) for e in plan.edges]
    assert pairs == sorted(pairs)
    assert pairs.count(("a", "b")) == 2  # distinct reasons stay visible
    assert len({(e.src, e.dst, e.reason) for e in plan.edges}) == len(plan.edges)
