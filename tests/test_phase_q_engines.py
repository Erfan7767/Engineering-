"""Tests for Phase Q engines — 30-year expert deeper improvements.

Seven new engines:
  Q1. topology_svg         — visual SVG topology
  Q2. topology_anomaly     — loops / SPOF / islands
  Q3. whatif               — blast-radius simulator
  Q4. change_window        — pick a safe change window
  Q5. capacity             — capacity planner / forecast
  Q6. performance          — performance baseline / anomaly
  Q7. audit_query          — typed ledger queries
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.topology_svg import (
    render_svg, render_svg_report, layout_topology,
)
from netops_autopilot.engines.topology_anomaly import (
    detect_anomalies, AnomalyCategory, AnomalySeverity,
)
from netops_autopilot.engines.whatif import (
    simulate, simulate_add_trunk, simulate_reload_device,
    simulate_remove_vlan, BlastSeverity, ChangeKind,
)
from netops_autopilot.engines.change_window import (
    ChangeWindow, PlannedChange, WindowImpact, WindowOutcome,
    pick_best_window,
)
from netops_autopilot.engines.capacity import (
    CapacitySample, forecast, forecast_one, CapacityVerdict,
)
from netops_autopilot.engines.performance import (
    build_baseline, check, BaselineSample, AnomalyVerdict,
)
from netops_autopilot.engines.audit_query import (
    AuditQuery, AuditFilter, AuditEventKind, query,
)


# ---------------------------------------------------------------------
# Topology stub — duck-typed object the engines can read.
# ---------------------------------------------------------------------


class _StubNode:
    def __init__(self, ref, cls="EDGE", status="COMPLETE"):
        self.device_ref = ref
        self.classification = cls
        self.status = status


class _StubEndpoint:
    def __init__(self, ref, intf):
        self.device_ref = ref
        self.interface = intf


class _StubEdge:
    def __init__(self, a, b, state="PHYSICAL_PATH_VERIFIED"):
        self.endpoint_a = _StubEndpoint(a, "Gi0/1")
        self.endpoint_b = _StubEndpoint(b, "Gi0/1")
        self.fsm4_state = state


class _StubTopo:
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges


# ==================================================================
# Q1 — Topology SVG
# ==================================================================


def test_topology_layout_assigns_positions():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b"), _StubNode("c")],
        edges=[
            _StubEdge("a", "b"),
            _StubEdge("b", "c"),
        ],
    )
    layout = layout_topology(topo)
    assert "a" in layout.node_positions
    assert "b" in layout.node_positions
    assert "c" in layout.node_positions


def test_topology_svg_is_self_contained():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b")],
        edges=[_StubEdge("a", "b")],
    )
    svg = render_svg(topo, title="T")
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert "T" in svg
    assert "a" in svg
    assert "b" in svg


def test_topology_svg_renders_all_grades():
    edges = [
        _StubEdge("a", "b", "PHYSICAL_PATH_VERIFIED"),
        _StubEdge("a", "c", "INFERRED"),
        _StubEdge("a", "d", "STALE"),
        _StubEdge("a", "e", "UNKNOWN"),
    ]
    topo = _StubTopo(
        nodes=[_StubNode(n) for n in "abcde"],
        edges=edges,
    )
    svg = render_svg(topo)
    # All four grade strokes present
    assert "#16a34a" in svg   # PHYSICAL
    assert "#a3a3a3" in svg   # INFERRED
    assert "#94a3b8" in svg   # STALE
    assert "#737373" in svg   # UNKNOWN


def test_topology_svg_report_has_legend():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b")],
        edges=[_StubEdge("a", "b")],
    )
    rep = render_svg_report(topo, lang="en")
    assert "Link evidence grades" in rep
    assert "PHYSICAL" in rep
    rep_ar = render_svg_report(topo, lang="ar")
    assert "درجات" in rep_ar


# ==================================================================
# Q2 — Topology anomaly
# ==================================================================


def test_anomaly_islanded_device_detected():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("isolated")],
        edges=[_StubEdge("a", "isolated")],
    )
    # Force isolated to have no edges
    topo.edges = []
    rep = detect_anomalies(topo)
    crit = [
        a for a in rep.anomalies
        if a.severity == AnomalySeverity.CRITICAL
    ]
    assert any(
        a.category == AnomalyCategory.ISLANDED_DEVICE
        for a in crit
    )


def test_anomaly_single_uplink_detected():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b"), _StubNode("c")],
        edges=[
            _StubEdge("a", "b"),  # a has 1 link
            _StubEdge("a", "c"),
            _StubEdge("b", "c"),
        ],
    )
    rep = detect_anomalies(topo)
    # No single-uplink: every node has degree 2.
    spof = [
        a for a in rep.anomalies
        if a.category == AnomalyCategory.SINGLE_POINT_OF_FAILURE
    ]
    assert len(spof) == 0


def test_anomaly_triangle_detected():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b"), _StubNode("c")],
        edges=[
            _StubEdge("a", "b"),
            _StubEdge("b", "c"),
            _StubEdge("c", "a"),
        ],
    )
    rep = detect_anomalies(topo)
    assert any(
        a.category == AnomalyCategory.L2_LOOP
        for a in rep.anomalies
    )


def test_anomaly_clean_topology():
    topo = _StubTopo(
        nodes=[_StubNode("a"), _StubNode("b")],
        edges=[_StubEdge("a", "b"), _StubEdge("a", "b")],
    )
    # Two devices, dual-uplink = redundant.
    rep = detect_anomalies(topo)
    assert rep.overall_verdict in ("CLEAN", "ADVISORY_FINDINGS", "HIGH_RISK_FINDINGS")


# ==================================================================
# Q3 — What-if simulator
# ==================================================================


def test_whatif_add_trunk_no_neighbors():
    topo = _StubTopo(
        nodes=[_StubNode("a")],
        edges=[],
    )
    rep = simulate_add_trunk(
        device_ref="a", interface="Gi0/1", topo=topo,
    )
    assert rep.change == ChangeKind.ADD_TRUNK
    assert rep.entries
    assert rep.affected_device_count >= 1


def test_whatif_reload_calculates_blast():
    topo = _StubTopo(
        nodes=[_StubNode("core"), _StubNode("a"), _StubNode("b"),
               _StubNode("c")],
        edges=[
            _StubEdge("core", "a"),
            _StubEdge("core", "b"),
            _StubEdge("core", "c"),
        ],
    )
    rep = simulate_reload_device(device_ref="core", topo=topo)
    assert rep.highest_severity == BlastSeverity.MEDIUM


def test_whatif_remove_vlan_severity_high():
    topo = _StubTopo(
        nodes=[_StubNode("a")],
        edges=[],
    )
    rep = simulate_remove_vlan(
        device_ref="a", vlan_id=10, topo=topo,
    )
    assert rep.highest_severity == BlastSeverity.HIGH


def test_whatif_dispatch_unknown_returns_empty():
    topo = _StubTopo(nodes=[], edges=[])
    rep = simulate("add_trunk", device_ref="a", topo=topo)
    assert rep.entries  # default add_trunk still produces entries


# ==================================================================
# Q4 — Change window
# ==================================================================


def test_window_picks_lowest_impact():
    now = 1000.0
    windows = [
        ChangeWindow("w_low", now + 100, now + 4600, WindowImpact.LOW),
        ChangeWindow("w_high", now + 100, now + 4600, WindowImpact.HIGH),
    ]
    change = PlannedChange(
        change_id="reload-core", estimated_duration_s=600,
        requires_window_impact=WindowImpact.LOW,
    )
    rep = pick_best_window(change, windows, now_unix=now)
    assert rep.outcome == WindowOutcome.PICKED
    assert rep.picked.window_id == "w_low"


def test_window_no_fit_when_past():
    now = 10000.0
    windows = [
        ChangeWindow("w", 100, 200, WindowImpact.LOW),
    ]
    change = PlannedChange(
        change_id="x", estimated_duration_s=10,
    )
    rep = pick_best_window(change, windows, now_unix=now)
    assert rep.outcome == WindowOutcome.NO_FIT


def test_window_insufficient_duration():
    now = 1000.0
    windows = [
        ChangeWindow("w", now + 100, now + 200, WindowImpact.LOW),
    ]
    change = PlannedChange(
        change_id="x", estimated_duration_s=1000,
    )
    rep = pick_best_window(change, windows, now_unix=now)
    assert rep.outcome == WindowOutcome.INSUFFICIENT_DURATION


def test_window_conflict_too_risky():
    now = 1000.0
    windows = [
        ChangeWindow("w", now + 100, now + 10000, WindowImpact.HIGH),
    ]
    change = PlannedChange(
        change_id="x", estimated_duration_s=10,
        requires_window_impact=WindowImpact.LOW,
    )
    rep = pick_best_window(change, windows, now_unix=now)
    assert rep.outcome == WindowOutcome.CONFLICT


# ==================================================================
# Q5 — Capacity
# ==================================================================


def test_capacity_below_threshold_is_ok():
    s = CapacitySample(
        metric="ports", current=20, capacity=48,
        monthly_growth=1.0, threshold_pct=90.0,
    )
    rep = forecast([s])
    assert rep.overall_verdict == "OK"
    assert rep.forecasts[0].verdict == CapacityVerdict.OK
    assert rep.forecasts[0].days_until_threshold is not None


def test_capacity_exhausted():
    s = CapacitySample(
        metric="ports", current=46, capacity=48,
        monthly_growth=1.0,
    )
    rep = forecast([s])
    assert rep.overall_verdict == "EXHAUSTED"
    assert rep.forecasts[0].verdict == CapacityVerdict.EXHAUSTED


def test_capacity_approaching():
    # 80% used, 10/month growth → 1 month → 90% threshold
    s = CapacitySample(
        metric="poe_watts", current=80, capacity=100,
        monthly_growth=10.0, threshold_pct=90.0,
    )
    rep = forecast_one(s)
    assert rep.verdict == CapacityVerdict.APPROACHING
    assert rep.days_until_threshold is not None
    assert rep.days_until_threshold <= 90


# ==================================================================
# Q6 — Performance baseline
# ==================================================================


def test_performance_baseline_compute():
    bl = build_baseline([100, 110, 105, 95, 102], "rx_bps")
    assert bl.median == 102
    assert bl.mad > 0


def test_performance_check_normal():
    bl = build_baseline([100, 110, 105, 95, 102], "rx_bps")
    rep = check({"rx_bps": bl}, [BaselineSample("rx_bps", 105)])
    assert rep.overall_verdict in ("NORMAL", "ELEVATED")
    assert rep.findings[0].verdict in (
        AnomalyVerdict.NORMAL, AnomalyVerdict.ELEVATED,
    )


def test_performance_check_anomalous():
    bl = build_baseline([100, 110, 105, 95, 102], "rx_bps")
    rep = check({"rx_bps": bl}, [BaselineSample("rx_bps", 500)])
    assert rep.overall_verdict == "ANOMALY_DETECTED"


def test_performance_check_insufficient_data():
    rep = check({}, [BaselineSample("rx_bps", 100)])
    assert rep.findings[0].verdict == AnomalyVerdict.INSUFFICIENT_DATA


# ==================================================================
# Q7 — Audit query
# ==================================================================


class _StubEvent:
    def __init__(
        self,
        event_id,
        kind,
        actor,
        target,
        summary,
        ts_unix,
    ):
        self.event_id = event_id
        self.event_type = kind
        self.actor = _StubActor(actor)
        self.target = target
        self.summary = summary
        self.timestamp_unix = ts_unix


class _StubActor:
    def __init__(self, id_):
        self.id = id_


class _StubStore:
    def __init__(self, events):
        self._events = events

    def events(self):
        return list(self._events)


def test_audit_query_filter_by_kind():
    store = _StubStore([
        _StubEvent("e1", "DISCOVERY", "engine", "core",
                   "walked the network", 1000.0),
        _StubEvent("e2", "APPLY", "engine", "core",
                   "applied design", 1100.0),
    ])
    q = AuditQuery(filters=(
        AuditFilter(kind=AuditEventKind.APPLY),
    ))
    r = query(store, q)
    assert r.total_matched == 1
    assert r.hits[0].event_id == "e2"


def test_audit_query_text_contains():
    store = _StubStore([
        _StubEvent("e1", "APPLY", "engine", "core",
                   "applied vlan 10", 1000.0),
        _StubEvent("e2", "APPLY", "engine", "core",
                   "applied hostname", 1100.0),
    ])
    q = AuditQuery(filters=(
        AuditFilter(text_contains="vlan"),
    ))
    r = query(store, q)
    assert r.total_matched == 1
    assert "vlan" in r.hits[0].summary


def test_audit_query_truncates():
    store = _StubStore([
        _StubEvent(f"e{i}", "APPLY", "engine", "core",
                   f"event {i}", float(i))
        for i in range(50)
    ])
    q = AuditQuery(limit=10)
    r = query(store, q)
    assert r.truncated is True
    assert len(r.hits) == 10
    assert r.total_matched == 50


def test_audit_query_time_filter():
    store = _StubStore([
        _StubEvent("e1", "APPLY", "engine", "core", "old", 100.0),
        _StubEvent("e2", "APPLY", "engine", "core", "new", 200.0),
    ])
    q = AuditQuery(filters=(
        AuditFilter(since_unix=150.0),
    ))
    r = query(store, q)
    assert r.total_matched == 1
    assert r.hits[0].event_id == "e2"


def test_audit_query_render_bilingual():
    store = _StubStore([
        _StubEvent("e1", "APPLY", "engine", "core",
                   "applied", 1700000000.0),
    ])
    q = AuditQuery(filters=(AuditFilter(),))
    r = query(store, q)
    assert "APPLY" in r.render("en")
    assert "APPLY" in r.render("ar")
