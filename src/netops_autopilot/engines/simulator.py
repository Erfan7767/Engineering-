"""Network Topology Simulator — predict reachability without applying.

A 30-year engineer, before deploying, asks "if I shut down
this uplink, can core-sw1 still reach the leaf switches?"
This module is the typed implementation: given the topology
and a hypothetical change, compute the new reachability
matrix and surface the devices that would lose
connectivity.

Design contract:

* **Pure function** — the simulator takes the topology as
  input and never mutates it.
* **Typed** — every result is a :class:`SimulatorResult`
  with a typed verdict per affected device.
* **Deterministic** — same inputs → same outputs.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum


class SimVerdict(str, Enum):
    __test__ = False

    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    ISLANDED = "ISLANDED"


@dataclass(frozen=True)
class ReachabilityChange:
    __test__ = False

    device: str
    before: SimVerdict
    after: SimVerdict

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"  {self.device}: {self.before.value} ← "
                f"{self.after.value}"
            )
        return (
            f"  {self.device}: {self.before.value} -> "
            f"{self.after.value}"
        )


@dataclass
class SimulatorResult:
    __test__ = False

    seed: str
    removed_edges: tuple[tuple[str, str], ...]
    changes: list[ReachabilityChange] = field(default_factory=list)

    @property
    def unreachable_after(self) -> list[str]:
        return [
            c.device for c in self.changes
            if c.after != SimVerdict.REACHABLE
        ]

    @property
    def overall_verdict(self) -> str:
        if any(
            c.after == SimVerdict.ISLANDED
            for c in self.changes
        ):
            return "ISLANDED_DEVICES"
        if self.unreachable_after:
            return "PARTIAL_OUTAGE"
        return "NO_IMPACT"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"محاكاة إزالة {len(self.removed_edges)} رابط\n"
                f"  النتيجة: {self.overall_verdict}"
            )
        else:
            head = (
                f"Simulation: removed {len(self.removed_edges)} link(s)\n"
                f"  Verdict: {self.overall_verdict}"
            )
        if not self.changes:
            return head + "\n  No reachability changes."
        return head + "\n" + "\n".join(
            c.render(lang=lang) for c in self.changes
        )


def _adjacency(edges: list) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        if hasattr(e, "endpoint_a"):
            a = e.endpoint_a.device_ref
            b = e.endpoint_b.device_ref
        else:
            a = e.a_key
            b = e.b_key
        adj[a].add(b)
        adj[b].add(a)
    return adj


def _bfs(
    start: str,
    adj: dict[str, set[str]],
) -> set[str]:
    seen: set[str] = {start}
    q: deque[str] = deque([start])
    while q:
        u = q.popleft()
        for v in adj.get(u, ()):
            if v in seen:
                continue
            seen.add(v)
            q.append(v)
    return seen


def simulate_remove_link(
    *,
    topo,
    seed: str,
    edge: tuple[str, str],
) -> SimulatorResult:
    """Simulate removing a single edge from the topology."""
    nodes = list(getattr(topo, "nodes", []) or [])
    edges = list(getattr(topo, "edges", []) or [])
    a_ref, b_ref = edge
    # Build adjacency as-is (before) and after the removal.
    adj_before = _adjacency(edges)
    # Build the "after" adjacency by removing every link that
    # connects (a, b).
    adj_after: dict[str, set[str]] = defaultdict(set)
    for e in edges:
        if hasattr(e, "endpoint_a"):
            a = e.endpoint_a.device_ref
            b = e.endpoint_b.device_ref
        else:
            a = e.a_key
            b = e.b_key
        if {a, b} == {a_ref, b_ref}:
            continue
        adj_after[a].add(b)
        adj_after[b].add(a)
    rep = SimulatorResult(
        seed=seed,
        removed_edges=(edge,),
    )
    before = _bfs(seed, adj_before)
    after = _bfs(seed, adj_after)
    for n in nodes:
        ref = n.device_ref
        before_v = (
            SimVerdict.REACHABLE if ref in before
            else SimVerdict.UNREACHABLE
        )
        after_v = (
            SimVerdict.REACHABLE if ref in after
            else SimVerdict.ISLANDED if ref not in adj_after
            else SimVerdict.UNREACHABLE
        )
        if before_v != after_v:
            rep.changes.append(ReachabilityChange(
                device=ref,
                before=before_v,
                after=after_v,
            ))
    return rep
