"""P1-34 Service Dependency Graph: ordering, closures, integrity."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.service_graph import ServiceGraph


@pytest.fixture(scope="module")
def graph():
    return ServiceGraph.load_builtin()


def test_builtin_graph_loads_with_spec_anchors(graph):
    names = graph.names()
    for required in ("dns", "ntp", "pki", "radius", "dot1x", "dhcp", "syslog", "ipsec"):
        assert required in names


def test_spec_chain_8021x_radius_dns_ntp_pki(graph):
    """§10/§13 chain: 802.1X → RADIUS → DNS/NTP; PKI → NTP."""
    assert graph.service("dot1x").depends_on == ("radius",)
    assert set(graph.service("radius").depends_on) == {"dns", "ntp"}
    assert graph.service("pki").depends_on == ("ntp",)


def test_dependencies_transitive_sorted(graph):
    deps = graph.dependencies_of("dot1x")
    assert deps == sorted(deps)
    assert set(deps) == {"radius", "dns", "ntp"}
    assert graph.dependencies_of("dot1x", transitive=False) == ["radius"]


def test_dependents_fan_out(graph):
    dependents = graph.dependents_of("dns")
    for expected in ("radius", "tacacs", "syslog", "internet_egress", "dot1x"):
        assert expected in dependents  # dot1x transitively via radius


def test_order_for_is_topological_and_deterministic(graph):
    order = graph.order_for(["dot1x"])
    assert set(order) == {"dot1x", "radius", "dns", "ntp"}
    assert order.index("ntp") < order.index("radius")
    assert order.index("dns") < order.index("radius")
    assert order.index("radius") < order.index("dot1x")
    # identical inputs ⇒ identical outputs, every time
    assert graph.order_for(["dot1x"]) == order


def test_order_for_multiple_roots(graph):
    order = graph.order_for(["https_mgmt", "ipsec"])
    assert order.index("ntp") < order.index("pki")
    assert order.index("pki") < order.index("https_mgmt")
    assert order.index("pki") < order.index("ipsec")


def test_unknown_service_is_typed(graph):
    with pytest.raises(Failure) as exc:
        graph.service("no_such_service")
    assert "SERVICE_UNKNOWN" in exc.value.causes[0]
    with pytest.raises(Failure):
        graph.order_for(["no_such_service"])


def test_provides_token_lookup(graph):
    assert graph.provides_token("aaa_radius") == ["radius"]
    assert graph.provides_token("certificates") == ["pki"]
    assert graph.provides_token("no_such_token") == []


def test_dangling_dependency_is_fatal_at_construction():
    with pytest.raises(Failure) as exc:
        ServiceGraph.from_data({"services": {"a": {"depends_on": ["ghost"]}}})
    assert "SERVICE_GRAPH_DANGLING" in exc.value.causes[0]


def test_cycle_is_fatal_at_construction():
    with pytest.raises(Failure) as exc:
        ServiceGraph.from_data({"services": {
            "a": {"depends_on": ["b"]},
            "b": {"depends_on": ["a"]},
        }})
    assert "SERVICE_GRAPH_CYCLE" in exc.value.causes[0]
