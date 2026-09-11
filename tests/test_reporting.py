"""Tests for the HTML + JSON reporting subsystem."""

from __future__ import annotations

import json

import pytest

from netops_autopilot.reporting.html_report import (
    ReportData,
    render_html_report,
    report_from_autopilot,
    _layout_topology_svg,
)
from netops_autopilot.reporting.json_report import render_json_report


# ----------------- HTML rendering -----------------


def test_html_renders_title_and_metadata():
    data = ReportData(
        run_id="abc",
        final="COMPLETE-STAGED",
        ledger_event_count=10,
        chain_ok=True,
    )
    out = render_html_report(data)
    assert "NetOps Autopilot" in out
    assert "abc" in out
    assert "10" in out
    assert "COMPLETE-STAGED" in out


def test_html_renders_phases():
    data = ReportData(
        run_id="x",
        final="OK",
        phases=[{"phase": "BOND", "status": "OK", "detail": "bound"}],
    )
    out = render_html_report(data)
    assert "BOND" in out
    assert "bound" in out


def test_html_renders_renders():
    data = ReportData(
        run_id="x",
        final="OK",
        renders={"router1": "interface Vlan10\n ip address 10.0.0.1/24"},
    )
    out = render_html_report(data)
    assert "router1" in out
    assert "interface Vlan10" in out


def test_html_renders_topology_svg():
    data = ReportData(
        run_id="x",
        final="OK",
        topology_nodes=[{"ref": "r1"}, {"ref": "r2"}],
        topology_edges=[{"a": "r1", "b": "r2"}],
    )
    out = render_html_report(data)
    assert "<svg" in out
    assert "r1" in out
    assert "r2" in out


def test_html_handles_empty_topology():
    data = ReportData(run_id="x", final="OK")
    out = render_html_report(data)
    assert "no devices" in out or "No devices" in out or "No gaps" in out


def test_html_escapes_special_characters():
    data = ReportData(
        run_id='<script>alert("xss")</script>',
        final="OK",
    )
    out = render_html_report(data)
    # XSS attempt must be escaped, not executed.
    assert "<script>" not in out or "&lt;script&gt;" in out
    assert "alert" in out  # text is preserved, just escaped


def test_html_renders_counters_table():
    data = ReportData(
        run_id="x",
        final="OK",
        counters={"netops_unverified_claims_total": 0, "netops_runs_total": 5},
    )
    out = render_html_report(data)
    assert "netops_unverified_claims_total" in out
    assert "netops_runs_total" in out
    assert "5" in out


def test_html_chain_tampered():
    data = ReportData(run_id="x", final="OK", chain_ok=False)
    out = render_html_report(data)
    assert "TAMPERED" in out


def test_html_self_contained_no_external_resources():
    """No <script src=...>, no <link href=...>, no external CSS @import."""
    data = ReportData(run_id="x", final="OK")
    out = render_html_report(data)
    # Strip out CSS string contents before checking (href="...css-data..." is OK).
    # The actual check: no fetch to http(s) URLs.
    assert "fetch(" not in out
    assert "XMLHttpRequest" not in out
    assert "@import" not in out
    # No raw <script src="https://...
    assert 'src="https' not in out
    assert 'src="http' not in out
    # Only inline event handlers, no external script tags.
    assert '<script src=' not in out
    assert '<link rel="stylesheet"' not in out


# ----------------- SVG layout -----------------


def test_layout_svg_handles_empty():
    out = _layout_topology_svg([], [])
    assert "<svg" in out


def test_layout_svg_deterministic():
    nodes = [{"ref": f"n{i}"} for i in range(8)]
    edges = [{"a": f"n{i}", "b": f"n{(i+1) % 8}"} for i in range(8)]
    a = _layout_topology_svg(nodes, edges)
    b = _layout_topology_svg(nodes, edges)
    assert a == b  # determinism


def test_layout_svg_handles_single_node():
    nodes = [{"ref": "solo"}]
    edges = []
    out = _layout_topology_svg(nodes, edges)
    assert "<svg" in out
    assert "solo" in out


# ----------------- JSON rendering -----------------


def test_json_basic_structure():
    class _Ph:
        phase = "BOND"
        status = "OK"
        detail = "x"
    class _R:
        final = "COMPLETE-STAGED"
        phases = [_Ph()]
        seed_family = "cisco/ios-xe"
        day0_state = "UNKNOWN"
    out = render_json_report(report=_R(), ledger_event_count=5, chain_ok=True)
    j = json.loads(out)
    assert j["schema"] == "netops-autopilot/run-report/v1"
    assert j["final"] == "COMPLETE-STAGED"
    assert j["ledger"]["event_count"] == 5
    assert j["ledger"]["chain_ok"] is True
    assert j["seed_family"] == "cisco/ios-xe"


def test_json_includes_counters_and_extra():
    class _R:
        final = "OK"
        phases = []
    out = render_json_report(
        report=_R(), ledger_event_count=0, chain_ok=True,
        counters={"x": 1}, extra={"vendor": "cisco"},
    )
    j = json.loads(out)
    assert j["counters"] == {"x": 1}
    assert j["extra"] == {"vendor": "cisco"}


def test_json_compact_mode():
    class _R:
        final = "OK"
        phases = []
    out_compact = render_json_report(report=_R(), ledger_event_count=0, chain_ok=True, pretty=False)
    out_pretty = render_json_report(report=_R(), ledger_event_count=0, chain_ok=True, pretty=True)
    # Compact should be shorter (no newlines/indentation).
    assert len(out_compact) < len(out_pretty)
    # And both parse to the same dict (modulo generated_at).
    j1 = json.loads(out_compact)
    j2 = json.loads(out_pretty)
    # generated_at differs by definition; ignore that one key.
    j1.pop("generated_at", None)
    j2.pop("generated_at", None)
    assert j1 == j2
