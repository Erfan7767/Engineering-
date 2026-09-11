"""Self-contained HTML report renderer — no external assets, no network calls.

Generates a single HTML file with:
- Header with run metadata
- Phase timeline
- Topology diagram (SVG, deterministic layout from graph edges)
- Evidence ledger summary
- Per-device rendered config (collapsed by default)
- Failure/typed-state callouts (T2)

The output is suitable for offline viewing, printing, and sharing in a lab
without exposing the device or the ledger secrets (L11).
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ReportData:
    """Aggregated data for HTML rendering (decoupled from the AutopilotReport)."""

    run_id: str
    final: str
    seed_family: Optional[str] = None
    day0_state: Optional[str] = None
    phases: list[dict[str, Any]] = field(default_factory=list)
    topology_ascii: str = ""
    topology_nodes: list[dict[str, Any]] = field(default_factory=list)
    topology_edges: list[dict[str, Any]] = field(default_factory=list)
    topology_gaps: list[dict[str, Any]] = field(default_factory=list)
    intent_summary: Optional[dict[str, Any]] = None
    design_summary: Optional[dict[str, Any]] = None
    renders: dict[str, str] = field(default_factory=dict)
    ledger_event_count: int = 0
    chain_ok: bool = True
    counters: dict[str, int] = field(default_factory=dict)
    execution: Optional[dict[str, Any]] = None
    notes: list[str] = field(default_factory=list)


# ------------------------- SVG topology layout -------------------------


def _layout_topology_svg(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    """Deterministic layered layout for the topology graph.

    Algorithm: place each node in a circle around the seed, then draw edges
    as straight lines. This is not "pretty" but it is honest (no fake
    positions), deterministic (replay-identical), and works for any size.
    """
    import math
    if not nodes:
        return '<svg viewBox="0 0 400 200"><text x="200" y="100" text-anchor="middle" fill="#999">no devices</text></svg>'
    cx, cy, r = 400, 250, 180
    n = len(nodes)
    pos = {}
    # First node (seed) at top
    pos[nodes[0].get("ref", "?")] = (cx, cy - r)
    rest = nodes[1:]
    for i, node in enumerate(rest):
        angle = (2 * math.pi * i) / max(1, len(rest))
        x = cx + r * math.sin(angle)
        y = cy - r * math.cos(angle) * 0.7  # squish vertically
        pos[node.get("ref", "?")] = (x, y)
    lines: list[str] = []
    for e in edges:
        a = e.get("a", "")
        b = e.get("b", "")
        if a in pos and b in pos:
            x1, y1 = pos[a]
            x2, y2 = pos[b]
            lines.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                f'stroke="#4a90e2" stroke-width="2" />'
            )
    circles: list[str] = []
    for ref, (x, y) in pos.items():
        circles.append(
            f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="28" fill="#2d3748" stroke="#4a90e2" stroke-width="2"/>'
            f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" fill="white" font-size="11" '
            f'font-family="monospace">{html.escape(ref[:12])}</text></g>'
        )
    return (
        '<svg viewBox="0 0 800 500" xmlns="http://www.w3.org/2000/svg" '
        'style="background:#1a202c;border-radius:8px;max-width:100%;height:auto">'
        + "".join(lines) + "".join(circles) + "</svg>"
    )


# ------------------------- The renderer -------------------------


_CSS = """
:root { --bg:#0f1419; --card:#1a202c; --text:#e2e8f0; --dim:#a0aec0; --accent:#4a90e2; --green:#48bb78; --red:#f56565; --yellow:#ed8936; }
* { box-sizing:border-box; }
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }
.container { max-width:1200px; margin:0 auto; padding:24px; }
h1 { color:var(--accent); margin:0 0 8px; font-size:28px; }
h2 { color:var(--accent); margin:32px 0 12px; font-size:20px; border-bottom:1px solid #2d3748; padding-bottom:8px; }
h3 { color:var(--text); font-size:16px; margin:16px 0 8px; }
.card { background:var(--card); border-radius:8px; padding:16px; margin-bottom:16px; box-shadow:0 2px 4px rgba(0,0,0,0.3); }
.kv { display:grid; grid-template-columns:200px 1fr; gap:8px; font-size:14px; }
.kv .k { color:var(--dim); }
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
.badge.ok { background:var(--green); color:#000; }
.badge.blocked { background:var(--red); color:#fff; }
.badge.human { background:var(--yellow); color:#000; }
.badge.typed { background:#9f7aea; color:#fff; }
.badge.running { background:#4299e1; color:#fff; }
pre { background:#0d1117; border:1px solid #2d3748; border-radius:4px; padding:12px; overflow-x:auto; font-size:12px; color:#c9d1d9; }
.topology-svg { background:var(--card); border-radius:8px; padding:16px; }
details { background:#0d1117; border:1px solid #2d3748; border-radius:4px; padding:8px 12px; margin:8px 0; }
summary { cursor:pointer; color:var(--accent); font-weight:600; }
.alert { background:#742a2a; border-left:4px solid var(--red); padding:12px; border-radius:4px; margin:12px 0; }
.alert.ok { background:#22543d; border-left-color:var(--green); }
.alert.warn { background:#744210; border-left-color:var(--yellow); }
table { width:100%; border-collapse:collapse; margin:8px 0; font-size:14px; }
th, td { text-align:left; padding:8px; border-bottom:1px solid #2d3748; }
th { color:var(--dim); font-weight:600; }
.footer { color:var(--dim); font-size:12px; text-align:center; margin-top:32px; padding-top:16px; border-top:1px solid #2d3748; }
.gaps li { color:var(--yellow); }
"""


def _esc(s: Any) -> str:
    return html.escape(str(s)) if s is not None else ""


def _badge(status: str) -> str:
    s = status.upper()
    cls = {
        "OK": "ok",
        "COMPLETE": "ok",
        "BLOCKED": "blocked",
        "HUMAN_DECISION": "human",
        "TYPED_STOP": "typed",
        "RUNNING": "running",
        "PARTIAL": "human",
        "ROLLED_BACK": "ok",
    }.get(s, "running")
    return f'<span class="badge {cls}">{_esc(status)}</span>'


def render_html_report(data: ReportData) -> str:
    """Render a ReportData as a self-contained HTML document."""
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    phases_html = "".join(
        f"<tr><td>{_esc(p.get('phase', ''))}</td><td>{_badge(p.get('status', ''))}</td>"
        f"<td>{_esc(p.get('detail', ''))}</td></tr>"
        for p in data.phases
    )
    final_cls = "ok" if data.final.startswith("COMPLETE") else "blocked"
    summary_alert = (
        f'<div class="alert {final_cls}"><strong>Final outcome:</strong> '
        f"{_badge(data.final)} &nbsp; {_esc(data.notes[0] if data.notes else '')}</div>"
    )
    topology_svg = _layout_topology_svg(data.topology_nodes, data.topology_edges)
    gaps_html = (
        "<ul class='gaps'>" + "".join(f"<li>{_esc(g)}</li>" for g in data.topology_gaps) + "</ul>"
        if data.topology_gaps else "<p style='color:var(--dim)'>No gaps detected.</p>"
    )
    renders_html = "".join(
        f"<details><summary>{_esc(ref)}</summary><pre>{_esc(cfg)}</pre></details>"
        for ref, cfg in data.renders.items()
    ) or "<p style='color:var(--dim)'>No rendered configurations.</p>"
    counters_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in sorted(data.counters.items())
    ) or "<tr><td colspan='2' style='color:var(--dim)'>no counters</td></tr>"
    intent_block = ""
    if data.intent_summary:
        intent_block = (
            "<div class='card'><h3>Intent</h3><pre>"
            + _esc(data.intent_summary)
            + "</pre></div>"
        )
    design_block = ""
    if data.design_summary:
        design_block = (
            "<div class='card'><h3>Design</h3><pre>"
            + _esc(data.design_summary)
            + "</pre></div>"
        )
    exec_block = ""
    if data.execution:
        exec_block = (
            "<div class='card'><h3>Execution</h3><pre>"
            + _esc(data.execution)
            + "</pre></div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetOps Autopilot · Run {_esc(data.run_id)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <h1>NetOps Autopilot · Run Report</h1>
  <div class="card">
    <div class="kv">
      <div class="k">Run ID</div><div>{_esc(data.run_id)}</div>
      <div class="k">Generated</div><div>{_esc(gen)}</div>
      <div class="k">Final</div><div>{_badge(data.final)}</div>
      <div class="k">Seed family</div><div>{_esc(data.seed_family or '—')}</div>
      <div class="k">Day-0 state</div><div>{_esc(data.day0_state or '—')}</div>
      <div class="k">Ledger events</div><div>{data.ledger_event_count}</div>
      <div class="k">Chain integrity</div><div>{'✓ OK' if data.chain_ok else '✗ TAMPERED'}</div>
    </div>
  </div>
  {summary_alert}
  <h2>Phase timeline</h2>
  <div class="card">
    <table>
      <thead><tr><th>Phase</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>{phases_html}</tbody>
    </table>
  </div>
  <h2>Topology</h2>
  <div class="card topology-svg">{topology_svg}</div>
  {("<h3>ASCII map</h3><pre>" + _esc(data.topology_ascii) + "</pre>") if data.topology_ascii else ""}
  <h2>Discovery gaps</h2>
  <div class="card">{gaps_html}</div>
  {intent_block}
  {design_block}
  <h2>Rendered configurations</h2>
  <div class="card">{renders_html}</div>
  {exec_block}
  <h2>Counters (T1–T6)</h2>
  <div class="card">
    <table><thead><tr><th>Counter</th><th>Value</th></tr></thead><tbody>{counters_rows}</tbody></table>
  </div>
  <div class="footer">
    Generated by NetOps Autopilot · evidence-driven, never a guess · 
    <a href="https://github.com/Erfan7767/Engineering-" style="color:var(--accent)">source</a>
  </div>
</div>
</body>
</html>
"""


def report_from_autopilot(
    report: Any,
    *,
    run_id: str,
    ledger_event_count: int,
    chain_ok: bool,
    counters: Optional[dict[str, int]] = None,
) -> ReportData:
    """Build a ``ReportData`` from an ``AutopilotReport`` instance."""
    phases = []
    for p in getattr(report, "phases", []):
        phases.append({
            "phase": getattr(p, "phase", "").value if hasattr(getattr(p, "phase", ""), "value") else str(getattr(p, "phase", "")),
            "status": getattr(p, "status", ""),
            "detail": getattr(p, "detail", ""),
        })
    topo = getattr(report, "topology", None)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    ascii = ""
    gaps: list[dict[str, Any]] = []
    if topo is not None:
        ascii = getattr(topo, "ascii", "")
        for n in getattr(topo, "nodes", []):
            nodes.append({
                "ref": getattr(n, "device_ref", getattr(n, "ref", "?")),
                "family": getattr(n, "vendor_family", ""),
                "status": getattr(n, "status", ""),
            })
        for e in getattr(topo, "edges", []):
            edges.append({
                "a": getattr(e, "a_device_ref", getattr(e, "a", "")),
                "b": getattr(e, "b_device_ref", getattr(e, "b", "")),
                "evidence": getattr(e, "evidence_refs", []),
            })
        for g in getattr(topo, "gaps", []):
            gaps.append({"detail": str(g)})
    renders: dict[str, str] = {}
    r_obj = getattr(report, "renders", None) or {}
    for ref, r in r_obj.items():
        try:
            renders[ref] = r.to_text() if hasattr(r, "to_text") else str(r)
        except Exception:  # noqa: BLE001
            renders[ref] = str(r)
    intent = getattr(report, "intent", None)
    intent_summary = None
    if intent is not None:
        intent_summary = {
            "blueprint": getattr(getattr(report, "elicitation", None), "blueprint_id", None),
            "zones": [getattr(z, "name", "") for z in getattr(intent, "zones", [])],
            "rules": len(getattr(intent, "rules", [])),
        }
    design = getattr(report, "design", None)
    design_summary = None
    if design is not None:
        design_summary = {
            "design_id": getattr(design, "design_id", ""),
            "roles": [(getattr(r, "device_ref", ""), getattr(r, "role", "")) for r in getattr(design, "roles", [])],
            "zones_count": len(getattr(design, "zones", [])),
            "uplinks_count": len(getattr(design, "uplinks", [])),
            "access_count": len(getattr(design, "access", [])),
        }
    return ReportData(
        run_id=run_id,
        final=getattr(report, "final", "UNKNOWN"),
        seed_family=getattr(report, "seed_family", None),
        day0_state=getattr(report, "day0_state", None),
        phases=phases,
        topology_ascii=ascii,
        topology_nodes=nodes,
        topology_edges=edges,
        topology_gaps=gaps,
        intent_summary=intent_summary,
        design_summary=design_summary,
        renders=renders,
        ledger_event_count=ledger_event_count,
        chain_ok=chain_ok,
        counters=counters or {},
        execution=getattr(report, "execution", None),
    )
