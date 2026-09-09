"""Topology Map Engine: honest, deterministic rendering of discovered reality."""

from netops_autopilot.engines.topology_map import TopologyMapEngine
from netops_autopilot.fsm import link_fsm as lf
from tests.test_discovery_crawl import (
    BACK_TABLE,
    BACK_VERSION,
    ScriptedFactory,
    _engine,
    _seed_session,
)
from tests.support.loopback import LoopbackSession


def _report():
    factory = ScriptedFactory(
        scripts={
            "core-sw1": _seed_session(),
            "core-sw2": LoopbackSession({
                "show version": BACK_VERSION,
                "show lldp neighbors detail": BACK_TABLE,
                "show cdp neighbors detail": b"",
            }),
        },
        refuse={"access-sw1": ("AUTH_REFUSED: default credentials rejected",)},
    )
    engine, store, twin, link_engine, allowlist = _engine(factory)
    report = engine.crawl(seed_ref="core-sw1", seed_family="cisco/ios-xe",
                          session_factory=factory, allowlist_of=lambda f: allowlist)
    return report, twin


def test_map_is_deterministic_byte_identical():
    report_a, twin_a = _report()
    report_b, twin_b = _report()
    map_a = TopologyMapEngine(twin_a).build(report_a)
    map_b = TopologyMapEngine(twin_b).build(report_b)
    assert map_a.ascii == map_b.ascii
    assert map_a.to_dict()["nodes"] == map_b.to_dict()["nodes"]


def test_map_renders_evidence_grades_and_gaps():
    report, twin = _report()
    topo = TopologyMapEngine(twin).build(report)
    text = topo.ascii

    # Seed first, identity facts verbatim.
    seed_line = next(l for l in text.splitlines() if l.startswith("[core-sw1]"))
    assert "SEED" in seed_line and "cisco/ios-xe" in seed_line and "C8300-1N-4T" in seed_line

    # The bidirectional link shows PROBABLE (passive ceiling — never upgraded).
    assert any("PROBABLE" in l and "core-sw2" in l for l in text.splitlines())
    # The one-sided link is visibly one-sided and marks the unreachable end.
    assert any("ONE-SIDED" in l and "access-sw1" in l and "UNREACHABLE" in l
               for l in text.splitlines())

    # Gaps list: unreachable device + the one-sided link both appear.
    assert any(g.startswith("DEVICE_UNREACHABLE access-sw1") for g in topo.gaps)
    assert any(g.startswith("LINK_EVIDENCE_BELOW_CONF") for g in topo.gaps)
    assert "GAPS LIST" in text

    # Never upgrades: CONFIRMED appears only in the legend, not on a link line.
    link_lines = [l for l in text.splitlines() if "════[" in l or "····[" in l]
    assert all("CONFIRMED]" not in l.replace(" · CONFIRMED", "") for l in link_lines)


def test_map_structure_counts_and_types():
    report, twin = _report()
    topo = TopologyMapEngine(twin).build(report)
    assert len(topo.nodes) == 3
    assert len(topo.edges) == 2
    assert topo.seed == "core-sw1"
    states = sorted(e.state for e in topo.edges)
    assert states == sorted([lf.DIRECT_NEIGHBOR_PROBABLE, lf.ONE_SIDED])
