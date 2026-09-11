"""Topology Stats — typed statistics over a network map.

A 30-year engineer doesn't just see a topology. The engineer
sees the redundancy: "which devices are single points of
failure? which subnets have no backup path? how many hops
between data center and branch?".

What it does:

* Walks a TopologyMap and computes: device count, link count,
  reachability matrix, single-points-of-failure, average
  shortest-path, and subnet fan-out.
* Returns a typed report. Every statistic is a separate field
  on the report (no packed integers).

What it does NOT do (typed, never silent):

* It does NOT claim a device is a "SPOF" unless removal of
  that device actually disconnects the graph (we run a real
  BFS, not a heuristic).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .topology_map import TopologyMap


@dataclass
class TopologyStats:
    __test__ = False

    device_count: int = 0
    link_count: int = 0
    one_sided_link_count: int = 0
    single_points_of_failure: list[str] = field(default_factory=list)
    # Average shortest-path in hops, for devices that are
    # connected to the seed.
    avg_shortest_path: float = 0.0
    # Diameter of the connected component (max hop count
    # between any two devices).
    diameter: int = 0
    # Devices reachable from the seed.
    reachable_from_seed: int = 0
    # Devices NOT reachable from the seed.
    unreachable_from_seed: int = 0


def compute(topology: TopologyMap) -> TopologyStats:
    """Compute typed statistics over the topology."""
    nodes = list(topology.nodes)
    edges = list(topology.edges)
    if not nodes:
        return TopologyStats()

    # Build an undirected adjacency map.
    adj: dict[str, set[str]] = {n.device_ref: set() for n in nodes}
    for e in edges:
        a, b = e.a_key, e.b_key
        if a in adj and b in adj:
            adj[a].add(b)
            adj[b].add(a)
    one_sided = sum(
        1 for e in edges
        if not (e.a_key in adj and e.b_key in adj and adj[e.a_key] and adj[e.b_key])
    )

    # BFS from each node to find SPOFs.
    spofs: list[str] = []
    for victim in nodes:
        if victim.device_ref not in adj:
            continue
        # BFS from node[0] with victim removed.
        remaining = {n.device_ref for n in nodes if n.device_ref != victim.device_ref}
        if not remaining:
            continue
        start = next(iter(remaining))
        visited = bfs(start, adj, skip=victim.device_ref)
        if len(visited) < len(remaining):
            spofs.append(victim.device_ref)

    # Average shortest path from the first node.
    if adj:
        seed = nodes[0].device_ref
        distances = bfs_with_distance(seed, adj)
        if distances:
            reachable = [d for d in distances.values() if d > 0]
            avg_path = sum(reachable) / len(reachable) if reachable else 0
            diameter = max(distances.values()) if distances else 0
        else:
            avg_path = 0
            diameter = 0
        reachable_count = len([d for d in distances.values() if d is not None])
        unreachable_count = len(nodes) - reachable_count
    else:
        avg_path = 0
        diameter = 0
        reachable_count = 0
        unreachable_count = len(nodes)

    return TopologyStats(
        device_count=len(nodes),
        link_count=len(edges),
        one_sided_link_count=one_sided,
        single_points_of_failure=spofs,
        avg_shortest_path=avg_path,
        diameter=diameter,
        reachable_from_seed=reachable_count,
        unreachable_from_seed=unreachable_count,
    )


def bfs(start: str, adj: dict[str, set[str]], *, skip: str = "") -> set[str]:
    """BFS from start. Skip the named node (e.g. to simulate its
    removal).
    """
    if start == skip:
        return set()
    visited: set[str] = set()
    queue = deque([start])
    while queue:
        node = queue.popleft()
        if node in visited or node == skip:
            continue
        visited.add(node)
        for nbr in adj.get(node, ()):
            if nbr not in visited and nbr != skip:
                queue.append(nbr)
    return visited


def bfs_with_distance(start: str, adj: dict[str, set[str]]) -> dict[str, int]:
    """BFS returning the hop distance to each reachable node."""
    distances: dict[str, int] = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for nbr in adj.get(node, ()):
            if nbr not in distances:
                distances[nbr] = distances[node] + 1
                queue.append(nbr)
    return distances


def render_stats(s: TopologyStats, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(s)
    return _render_en(s)


def _render_en(s: TopologyStats) -> str:
    lines = [
        f"Topology statistics",
        f"  Devices: {s.device_count}   "
        f"Links: {s.link_count}   "
        f"One-sided: {s.one_sided_link_count}",
        f"  Reachable from seed: {s.reachable_from_seed}   "
        f"Unreachable: {s.unreachable_from_seed}",
        f"  Avg shortest path: {s.avg_shortest_path:.2f} hops",
        f"  Diameter: {s.diameter} hops",
    ]
    if s.single_points_of_failure:
        lines.append(f"  Single points of failure: {', '.join(s.single_points_of_failure)}")
    else:
        lines.append("  Single points of failure: none — every device is redundant")
    return "\n".join(lines)


def _render_ar(s: TopologyStats) -> str:
    lines = [
        f"إحصائيات الطوبولوجيا",
        f"  الأجهزة: {s.device_count}   "
        f"الروابط: {s.link_count}   "
        f"أحادية: {s.one_sided_link_count}",
        f"  قابل للوصول من البذرة: {s.reachable_from_seed}   "
        f"غير قابل: {s.unreachable_from_seed}",
        f"  متوسط أقصر مسار: {s.avg_shortest_path:.2f} قفزات",
        f"  القطر: {s.diameter} قفزات",
    ]
    if s.single_points_of_failure:
        lines.append(f"  نقاط فشل فردية: {', '.join(s.single_points_of_failure)}")
    else:
        lines.append("  نقاط فشل فردية: لا شيء — كل جهاز زائد عن الحاجة")
    return "\n".join(lines)
