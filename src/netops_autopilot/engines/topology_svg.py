"""Topology SVG Renderer — visual map of the discovered network.

A 30-year engineer's whiteboard is the SVG: circles for
devices, arrows for links, colour-coded by FSM grade. This
module turns a :class:`TopologyMap` into a self-contained SVG
string that any modern browser renders inline. No external
libraries, no JavaScript — just shapes, lines, and text.

Design contract:

* **Deterministic layout** — the same topology always
  produces the same SVG. BFS layers from the seed, then
  arrange siblings in sorted order.
* **FSM-graded** — every link carries its evidence grade
  (PHYSICAL_PATH_VERIFIED / DIRECT_NEIGHBOR_CONFIRMED / etc).
  The colour and dash pattern reflect that grade.
* **Self-contained** — no external CSS, fonts, or images.
  Inline styles only. The SVG renders identically inside
  the chat preview iframe and in a downloaded file.
* **Typed output** — :func:`render_svg` returns a string.
  :func:`render_svg_report` adds a typed legend and stats.
"""

from __future__ import annotations

import html
import math
from dataclasses import dataclass, field
from typing import Iterable

from ..fsm import link_fsm as lf
from .topology_map import MapEdge, MapNode, TopologyMap


# Per-grade style. Colour palette is intentionally high-contrast.
_GRADE_STYLE: dict[str, tuple[str, str, str]] = {
    # grade -> (stroke_color, dash_array, label)
    lf.PHYSICAL_PATH_VERIFIED: ("#16a34a", "0", "PHYSICAL"),
    lf.DIRECT_NEIGHBOR_CONFIRMED: ("#22c55e", "0", "CONFIRMED"),
    lf.DIRECT_NEIGHBOR_PROBABLE: ("#84cc16", "4,2", "PROBABLE"),
    lf.INFERRED: ("#a3a3a3", "6,3", "INFERRED"),
    lf.ONE_SIDED: ("#facc15", "2,2", "ONE-SIDED"),
    lf.INTERMEDIATE_SUSPECTED: ("#fb923c", "5,3,1,3", "INTERMEDIATE?"),
    lf.CONFLICTING: ("#dc2626", "3,3", "CONFLICTING"),
    lf.STALE: ("#94a3b8", "1,4", "STALE"),
    lf.UNKNOWN: ("#737373", "1,1", "UNKNOWN"),
}


_STATUS_FILL: dict[str, str] = {
    "COMPLETE": "#dcfce7",
    "REACHABLE": "#fef3c7",
    "UNREACHABLE": "#fee2e2",
    "PARTIAL": "#fde68a",
    "BLOCKED": "#fecaca",
    "UNKNOWN": "#f3f4f6",
}


@dataclass(frozen=True)
class SvgLayout:
    __test__ = False

    width: int
    height: int
    node_positions: dict[str, tuple[float, float]]


def _edge_endpoints(e) -> tuple[str, str] | None:
    """Return (a_ref, b_ref) for any edge shape.

    The production :class:`MapEdge` exposes ``a_key`` /
    ``b_key`` (the device keys); the older test stub exposes
    ``endpoint_a.device_ref`` / ``endpoint_b.device_ref``.
    """
    if hasattr(e, "endpoint_a") and hasattr(e, "endpoint_b"):
        return (
            e.endpoint_a.device_ref,
            e.endpoint_b.device_ref,
        )
    if hasattr(e, "a_key") and hasattr(e, "b_key"):
        return e.a_key, e.b_key
    return None


def _edge_state(e) -> str:
    if hasattr(e, "fsm4_state"):
        return e.fsm4_state
    if hasattr(e, "state"):
        return e.state
    return "UNKNOWN"


def layout_topology(topo) -> SvgLayout:
    """Compute deterministic (x, y) positions for every node.

    BFS from the first node, then arrange each layer as a
    horizontal row centred on the seed.
    """
    nodes = list(getattr(topo, "nodes", []) or [])
    edges = list(getattr(topo, "edges", []) or [])
    if not nodes:
        return SvgLayout(width=400, height=200, node_positions={})
    # Build adjacency for BFS
    by_ref = {n.device_ref: n for n in nodes}
    edges_by_node: dict[str, list] = {n: [] for n in by_ref}
    for e in edges:
        ep = _edge_endpoints(e)
        if ep is None:
            continue
        a, b = ep
        edges_by_node.setdefault(a, []).append(e)
        edges_by_node.setdefault(b, []).append(e)
    # BFS layers
    seed = nodes[0].device_ref
    layers: list[list[str]] = [[seed]]
    seen: set[str] = {seed}
    frontier: list[str] = [seed]
    while frontier:
        nxt: list[str] = []
        for u in frontier:
            for e in edges_by_node.get(u, []):
                ep = _edge_endpoints(e)
                if ep is None:
                    continue
                a, b = ep
                v = b if a == u else a
                if v in seen:
                    continue
                seen.add(v)
                nxt.append(v)
        if not nxt:
            break
        nxt.sort()
        layers.append(nxt)
        frontier = nxt
    # Place nodes
    width = max(900, 220 * max(len(layer) for layer in layers) + 80)
    height = 90 * len(layers) + 80
    positions: dict[str, tuple[float, float]] = {}
    cy = 60
    for layer in layers:
        n = len(layer)
        if n == 0:
            continue
        gap = width / (n + 1)
        for i, ref in enumerate(layer):
            x = gap * (i + 1)
            positions[ref] = (x, cy)
        cy += 90
    return SvgLayout(
        width=width,
        height=height,
        node_positions=positions,
    )


def render_svg(
    topo: TopologyMap,
    *,
    title: str = "Network Topology",
) -> str:
    """Render the topology to a self-contained SVG string."""
    layout = layout_topology(topo)
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {layout.width} {layout.height}" '
        f'width="{layout.width}" height="{layout.height}" '
        f'role="img" aria-label="{html.escape(title)}">'
    )
    # Inline style block — only what we use.
    parts.append(
        "<style>"
        ".ttl{font:600 14px sans-serif;fill:#0f172a;}"
        ".lbl{font:500 11px sans-serif;fill:#1e293b;}"
        ".sub{font:400 10px sans-serif;fill:#475569;}"
        ".edge{stroke-width:2;fill:none;}"
        ".node-circ{stroke:#1e293b;stroke-width:1.2;}"
        "</style>"
    )
    # Title
    parts.append(
        f'<text x="{layout.width // 2}" y="24" text-anchor="middle" '
        f'class="ttl">{html.escape(title)}</text>'
    )
    # Edges first (so they render below nodes)
    for e in topo.edges:
        ep = _edge_endpoints(e)
        if ep is None:
            continue
        a_ref, b_ref = ep
        if a_ref not in layout.node_positions or \
           b_ref not in layout.node_positions:
            continue
        ax, ay = layout.node_positions[a_ref]
        bx, by = layout.node_positions[b_ref]
        grade = _edge_state(e)
        stroke, dash, _ = _GRADE_STYLE.get(
            grade, ("#737373", "1,1", "UNKNOWN"),
        )
        # Curved path for clarity
        mid_x = (ax + bx) / 2
        mid_y = (ay + by) / 2 - 20
        parts.append(
            f'<path d="M {ax:.1f} {ay:.1f} '
            f'Q {mid_x:.1f} {mid_y:.1f} '
            f'{bx:.1f} {by:.1f}" '
            f'class="edge" stroke="{stroke}" '
            f'stroke-dasharray="{dash}" '
            f'data-grade="{html.escape(grade)}">'
            f'<title>{html.escape(grade)}: '
            f'{html.escape(a_ref)} '
            f'↔ {html.escape(b_ref)}</title>'
            f'</path>'
        )
    # Nodes
    for n in topo.nodes:
        if n.device_ref not in layout.node_positions:
            continue
        x, y = layout.node_positions[n.device_ref]
        fill = _STATUS_FILL.get(
            str(n.status).upper(),
            _STATUS_FILL["UNKNOWN"],
        )
        # Circle
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="22" '
            f'class="node-circ" fill="{fill}" />'
        )
        # Label
        parts.append(
            f'<text x="{x:.1f}" y="{y - 30:.1f}" '
            f'text-anchor="middle" class="lbl">'
            f'{html.escape(n.device_ref)}</text>'
        )
        # Sub label: role + status
        sub = f"{n.classification or '?'} · {n.status or '?'}"
        parts.append(
            f'<text x="{x:.1f}" y="{y + 38:.1f}" '
            f'text-anchor="middle" class="sub">'
            f'{html.escape(sub)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def render_svg_report(
    topo: TopologyMap,
    *,
    title: str = "Network Topology",
    lang: str = "en",
) -> str:
    """Render an SVG plus a typed legend + counts."""
    svg = render_svg(topo, title=title)
    counts: dict[str, int] = {}
    for e in topo.edges:
        s = _edge_state(e)
        counts[s] = counts.get(s, 0) + 1
    status_counts: dict[str, int] = {}
    for n in topo.nodes:
        s = str(n.status).upper()
        status_counts[s] = status_counts.get(s, 0) + 1
    legend_rows: list[str] = []
    for grade, (color, dash, label) in _GRADE_STYLE.items():
        legend_rows.append(
            f'<div class="lg-row">'
            f'<svg width="32" height="6">'
            f'<line x1="0" y1="3" x2="32" y2="3" '
            f'stroke="{color}" stroke-width="2" '
            f'stroke-dasharray="{dash}" /></svg>'
            f'<span>{label}</span>'
            f'<span class="lg-n">{counts.get(grade, 0)}</span>'
            f'</div>'
        )
    legend_html = (
        "<div class='legend'>"
        "<div class='lg-h'>"
        + ("Link evidence grades" if lang == "en" else "درجات إثبات الرابط")
        + "</div>"
        + "".join(legend_rows)
        + "</div>"
    )
    status_rows: list[str] = []
    for s, c in sorted(status_counts.items()):
        status_rows.append(
            f"<li>{html.escape(s)}: {c}</li>"
        )
    summary = (
        f"<div class='summary'>"
        f"<div class='sum-h'>"
        + ("Network summary" if lang == "en" else "ملخص الشبكة")
        + f"</div>"
        f"<ul>"
        f"<li>"
        + (f"Devices: {len(topo.nodes)}" if lang == "en"
           else f"الأجهزة: {len(topo.nodes)}")
        + f"</li>"
        f"<li>"
        + (f"Links: {len(topo.edges)}" if lang == "en"
           else f"الروابط: {len(topo.edges)}")
        + f"</li>"
        + "".join(status_rows)
        + f"</ul>"
        f"</div>"
    )
    style = (
        "<style>"
        ".legend,.summary{font:12px sans-serif;color:#0f172a;"
        "background:#f8fafc;border:1px solid #e2e8f0;"
        "border-radius:6px;padding:8px 12px;margin-top:8px;"
        "display:inline-block;vertical-align:top;}"
        ".lg-h,.sum-h{font-weight:600;margin-bottom:4px;}"
        ".lg-row{display:flex;align-items:center;gap:8px;}"
        ".lg-n{margin-left:auto;color:#475569;}"
        ".summary ul{margin:4px 0 0 0;padding:0 0 0 16px;}"
        "</style>"
    )
    return (
        "<div class='topology-wrap'>"
        + svg
        + "<div>"
        + legend_html
        + summary
        + "</div>"
        + style
        + "</div>"
    )
