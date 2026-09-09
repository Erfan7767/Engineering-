"""Topology Map Engine — renders the discovered network from EVIDENCE only.

Inputs are the Discovery Crawl Report and the Twin; every rendered fact is
either evidence-backed (device identity, link endpoint, FSM-4 grade) or an
explicitly typed gap (UNKNOWN identity, UNREACHABLE device, link below the
passive ceiling). ASCII layout is DETERMINISTIC: BFS layers from the seed
over link-state-graded edges, sorted at every level; replaying renders the
identical string. A link is drawn with its evidence grade — the map never
upgrades certainty (L01/L14).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..fsm import link_fsm as lf
from ..twin.twin import DigitalTwin
from .discovery_crawl import CrawlReport, DeviceResult, DeviceStatus

_GRADE_STYLE = {
    lf.PHYSICAL_PATH_VERIFIED: ("════", "PHYSICAL_PATH_VERIFIED"),
    lf.DIRECT_NEIGHBOR_CONFIRMED: ("════", "CONFIRMED"),
    lf.DIRECT_NEIGHBOR_PROBABLE: ("════", "PROBABLE"),
    lf.INFERRED: ("┄┄┄┄", "INFERRED"),
    lf.ONE_SIDED: ("····", "ONE-SIDED"),
    lf.INTERMEDIATE_SUSPECTED: ("┄┄┄┄", "INTERMEDIATE?"),
    lf.CONFLICTING: ("┄╳┄╳", "CONFLICTING"),
    lf.STALE: ("░░░░", "STALE"),
    lf.UNKNOWN: ("????", "UNKNOWN"),
}


@dataclass(frozen=True)
class MapNode:
    device_ref: str
    classification: str
    status: str
    vendor_family: Optional[str]
    model: Optional[str]
    version: Optional[str]
    serial: Optional[str]
    row: int
    col: int


@dataclass(frozen=True)
class MapEdge:
    link_id: str
    a_key: str
    b_key: str
    state: str
    protocols: tuple[str, ...]


@dataclass(frozen=True)
class TopologyMap:
    nodes: tuple[MapNode, ...]
    edges: tuple[MapEdge, ...]
    seed: Optional[str]
    gaps: tuple[str, ...]
    ascii: str

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "nodes": [n.__dict__ for n in self.nodes],
            "edges": [e.__dict__ for e in self.edges],
            "gaps": list(self.gaps),
        }


class TopologyMapEngine:
    """Deterministic BFS layout + renderer."""

    def __init__(self, twin: DigitalTwin) -> None:
        self._twin = twin

    # ------------------------------------------------------------------ build
    def build(self, report: CrawlReport) -> TopologyMap:
        devices = {d.device_ref: d for d in report.devices}
        adjacency: dict[str, list[tuple[str, str]]] = {}
        for link in report.links:
            a_dev, b_dev = link.endpoint_a.device_ref, link.endpoint_b.device_ref
            adjacency.setdefault(a_dev, []).append((b_dev, link.fsm4_state))
            adjacency.setdefault(b_dev, []).append((a_dev, link.fsm4_state))
        for dev in adjacency:
            adjacency[dev].sort(key=lambda item: (item[0], item[1]))

        seed = next((d.device_ref for d in report.devices if d.classification.value == "SEED"), None)
        # BFS layering (row = BFS depth); unreached/orphans go to the last row.
        rows: dict[str, int] = {}
        if seed is not None:
            wave = [seed]
            depth = 0
            while wave:
                nxt: list[str] = []
                for dev in sorted(w for w in wave if w not in rows):
                    rows[dev] = depth
                    for neighbor, _state in adjacency.get(dev, []):
                        if neighbor not in rows and neighbor not in nxt:
                            nxt.append(neighbor)
                wave = nxt
                depth += 1
        orphan_row = (max(rows.values()) + 1) if rows else 0
        ordered = sorted(
            devices,
            key=lambda ref: (rows.get(ref, orphan_row), ref != seed, ref))
        nodes: list[MapNode] = []
        per_row_counts: dict[int, int] = {}
        for ref in sorted(ordered, key=lambda r: (rows.get(r, orphan_row), r != seed, r)):
            row = rows.get(ref, orphan_row)
            col = per_row_counts.get(row, 0)
            per_row_counts[row] = col + 1
            dev = devices[ref]
            ident = dev.identity
            nodes.append(MapNode(
                device_ref=ref,
                classification=dev.classification.value,
                status=dev.status.value,
                vendor_family=ident.vendor_family if ident else None,
                model=ident.model if ident else None,
                version=ident.version if ident else None,
                serial=ident.serial if ident else None,
                row=row, col=col))

        edges = tuple(MapEdge(
            link_id=l.link_id,
            a_key=l.endpoint_a.key(), b_key=l.endpoint_b.key(),
            state=l.fsm4_state, protocols=l.protocols) for l in
            sorted(report.links, key=lambda l: l.link_id))

        gap_lines = self._gaps(report)
        ascii_text = self._render(report, nodes, edges, seed, adjacency, gap_lines)
        return TopologyMap(nodes=tuple(nodes), edges=edges, seed=seed,
                           gaps=tuple(gap_lines), ascii=ascii_text)

    # ------------------------------------------------------------------- gaps
    def _gaps(self, report: CrawlReport) -> list[str]:
        out: list[str] = []
        for dev in sorted(report.devices, key=lambda d: d.device_ref):
            ident = dev.identity
            missing: list[str] = []
            if ident is None:
                missing = ["vendor_family", "model", "version", "serial"]
            else:
                if ident.vendor_family is None:
                    missing.append("vendor_family")
                if ident.model is None:
                    missing.append("model")
                if ident.version is None:
                    missing.append("version")
                if ident.serial is None:
                    missing.append("serial")
            if missing:
                out.append(f"IDENTITY_INCOMPLETE {dev.device_ref}: {', '.join(missing)}")
            if dev.status is DeviceStatus.UNREACHABLE:
                cause = dev.rejection_reasons[0] if dev.rejection_reasons else "cause UNKNOWN"
                out.append(f"DEVICE_UNREACHABLE {dev.device_ref}: {cause}")
            if dev.status is DeviceStatus.PARTIAL:
                collected, planned = dev.counts()
                missing_cmds = sorted(c.command for c in dev.commands
                                      if c.status.value != "COLLECTED")
                out.append(f"DISCOVERY_PARTIAL {dev.device_ref}: {collected}/{planned} "
                           f"commands; failed: {', '.join(missing_cmds)}")
        for link in report.links:
            if link.fsm4_state in (lf.ONE_SIDED, lf.INFERRED, lf.INTERMEDIATE_SUSPECTED,
                                   lf.CONFLICTING, lf.STALE, lf.UNKNOWN):
                out.append(f"LINK_EVIDENCE_BELOW_CONF {link.link_id}: FSM-4={link.fsm4_state}")
        return sorted(set(out))

    # ----------------------------------------------------------------- render
    def _render(self, report: CrawlReport, nodes: list[MapNode], edges: tuple[MapEdge, ...],
                seed: Optional[str], adjacency: dict[str, list[tuple[str, str]]],
                gap_lines: list[str]) -> str:
        width = 96
        header = f"NETWORK MAP — evidence-graded (FSM-4) · {len(nodes)} devices · {len(edges)} links"
        lines = [header, "=" * min(width, len(header) + 20)]

        # Per-node cards with their incidence edges (tree-style, seed first).
        dev_by_ref = {n.device_ref: n for n in nodes}
        drawn: set[str] = set()
        order = [n.device_ref for n in sorted(nodes, key=lambda n: (n.row, n.device_ref != seed, n.device_ref))]
        for ref in order:
            node = dev_by_ref[ref]
            lines.append(self._device_card(node, report))
            drawn.add(ref)
            incidences = [e for e in edges if ref in (e.a_key.split("|")[0], e.b_key.split("|")[0])]
            for e in sorted(incidences, key=lambda e: e.link_id):
                lines.append("  " + self._edge_line(ref, e, dev_by_ref))
        if not nodes:
            lines.append("(no devices discovered)")

        lines.append("")
        lines.append("EVIDENCE LEGEND: ════ confirmed/probable (passive ceiling) · "
                     "···· one-sided · ┄┄┄┄ inferred/intermediary · ┄╳┄╳ conflicting · "
                     "░░░░ stale · ???? unknown")
        if gap_lines:
            lines.append("")
            lines.append(f"GAPS LIST ({len(gap_lines)}) — every gap blocks assumptions, never hidden:")
            for g in gap_lines:
                lines.append(f"  !! {g}")
        return "\n".join(lines)

    def _device_card(self, node: MapNode, report: CrawlReport) -> str:
        ident_bits: list[str] = []
        ident_bits.append(node.vendor_family or "vendor UNKNOWN")
        ident_bits.append(node.model or "model UNKNOWN")
        ident_bits.append(node.version or "version UNKNOWN")
        if node.serial:
            ident_bits.append(f"SN {node.serial}")
        flags = [node.classification]
        if node.status != "COMPLETE":
            flags.append(node.status)
        return f"[{node.device_ref}] ({', '.join(flags)}) — " + " · ".join(ident_bits)

    def _edge_line(self, perspective: str, edge: MapEdge, nodes: dict[str, MapNode]) -> str:
        style, label = _GRADE_STYLE[edge.state]
        protos = "+".join(edge.protocols) if edge.protocols else "?"
        a_dev = edge.a_key.split("|")[0]
        if perspective == a_dev:
            local, remote = edge.a_key, edge.b_key
        else:
            local, remote = edge.b_key, edge.a_key
        remote_dev = remote.split("|")[0]
        remote_port = remote.split("|", 1)[1] if "|" in remote else "?"
        local_port = local.split("|", 1)[1] if "|" in local else "?"
        status_note = ""
        remote_node = nodes.get(remote_dev)
        if remote_node is not None and remote_node.status == "UNREACHABLE":
            status_note = "  (UNREACHABLE — evidence from this side only)"
        return (f"{local_port:<18} {style}[{protos} · {label}]{style} "
                f"{remote_port:<18} [{remote_dev}]{status_note}")
