"""E12 Dependency DAG Engine — DECIDE deployment order (D0-02, FSM-2 2.2).

Built from Config IR ``requires/provides/blocks/depends_on`` plus the
P1-34 service dependency graph (D0-08 §6). Permanent constraints of guard
2.2 realized here:
* topological sort TOTAL — every node appears exactly once, cycles are
  typed failures, never broken arbitrarily;
* management-plane nodes order FIRST among ready nodes (tie-break rule);
* controller-before-adoption / underlay-before-overlay / AAA-NTP-PKI-before-
  dependents are enforced through the same token mechanism: those relations
  must be DECLARED as requires/provides or service facts — the engine never
  infers them silently (L01).

The fabric's DEPENDENCY stage runs the same checks as validation findings;
this engine fails fast with typed Failures because a DAG is a plan, and a
plan with an unresolved edge must never be handed to execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core.failures import Failure, FailureClass
from .config_ir import ConfigIR, IRNode
from .service_graph import ServiceGraph

SERVICE_TOKEN_PREFIX = "service:"


@dataclass(frozen=True)
class DAGEdge:
    src: str  # node_id that must run first
    dst: str
    reason: str  # DEPENDS_ON | REQUIRES_TOKEN:<token> | SERVICE_DEP:<service>


@dataclass(frozen=True)
class DAGPlan:
    ir_id: str
    order: tuple[str, ...]        # total topological order (guard 2.2)
    edges: tuple[DAGEdge, ...]    # deduplicated, sorted deterministically
    mgmt_first_applied: bool      # True when the mgmt tie-break actually reordered


class DependencyDAGEngine:
    def __init__(self, service_graph: Optional[ServiceGraph] = None) -> None:
        self._services = service_graph

    # ----------------------------------------------------------------- build
    def build(self, ir: ConfigIR,
              external_provides: frozenset[str] = frozenset()) -> DAGPlan:
        nodes = {n.node_id: n for n in ir.nodes}
        providers = self._check_provides(ir)
        edges: set[tuple[str, str, str]] = set()

        for node in ir.nodes:
            for dep in node.depends_on:
                if dep not in nodes:
                    raise Failure(cls=FailureClass.BLOCKED,
                                  causes=(f"UNKNOWN_DEPENDS_ON: {node.node_id} depends_on {dep!r} — not in this IR",))
                edges.add((dep, node.node_id, "DEPENDS_ON"))

            for token in node.requires:
                if token in external_provides:
                    continue
                if token not in providers:
                    raise Failure(cls=FailureClass.BLOCKED,
                                  causes=(f"UNSATISFIED_REQUIRES: {node.node_id} requires {token!r} — nothing provides it",))
                for owner in providers[token]:
                    if owner != node.node_id:
                        edges.add((owner, node.node_id, f"REQUIRES_TOKEN:{token}"))

            self._check_conflicts(node, providers)
            edges.update(self._service_edges(node, ir, external_provides))

        order, mgmt_first_applied = self._topological(ir.nodes, edges)
        return DAGPlan(ir_id=ir.ir_id, order=tuple(order),
                       edges=tuple(DAGEdge(s, d, r) for s, d, r in sorted(edges)),
                       mgmt_first_applied=mgmt_first_applied)

    # ------------------------------------------------------------- validation
    @staticmethod
    def _check_provides(ir: ConfigIR) -> dict[str, list[str]]:
        providers: dict[str, list[str]] = {}
        for node in ir.nodes:
            for token in node.provides:
                providers.setdefault(token, []).append(node.node_id)
        for token, owners in sorted(providers.items()):
            if len(owners) > 1:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"DUPLICATE_PROVIDES: token {token!r} provided by {sorted(owners)}",))
        return providers

    @staticmethod
    def _check_conflicts(node: IRNode, providers: dict[str, list[str]]) -> None:
        for token in sorted(node.conflicts):
            if token in providers and providers[token] != [node.node_id]:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"CONFLICT: {node.node_id} declares conflict with {token!r} "
                                      f"but {providers[token]} provide it in the same change",))
        for token in sorted(node.blocks):
            if token in providers and providers[token] != [node.node_id]:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"BLOCKS_VIOLATION: {node.node_id} blocks {token!r} "
                                      f"but {providers[token]} provide it in the same change",))

    def _service_edges(self, node: IRNode, ir: ConfigIR,
                       external_provides: frozenset[str]) -> set[tuple[str, str, str]]:
        """Service-level ordering from P1-34: a node whose feature is a known
        service may only run after the services it depends on are provided."""
        if self._services is None or node.feature not in self._services.names():
            return set()
        out: set[tuple[str, str, str]] = set()
        for dep in self._services.service(node.feature).depends_on:
            dep_token = f"{SERVICE_TOKEN_PREFIX}{dep}"
            owners = [n.node_id for n in ir.nodes
                      if n.node_id != node.node_id
                      and (n.feature == dep or dep_token in n.provides)]
            if owners:
                for owner in sorted(owners):
                    out.add((owner, node.node_id, f"SERVICE_DEP:{dep}"))
            elif dep_token not in external_provides:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"SERVICE_DEP_UNMET: {node.node_id} uses service {node.feature!r} "
                                      f"which depends on {dep!r} — neither provided in IR nor external",))
        return out

    # ------------------------------------------------------------ topological
    @staticmethod
    def _topological(nodes_tuple, edges) -> tuple[list[str], bool]:
        """Deterministic Kahn. Frontier ordered by (non-mgmt, node_id) so
        management-plane nodes deploy first among ready nodes (guard 2.2)."""
        nodes = sorted(n.node_id for n in nodes_tuple)
        mgmt = {n.node_id for n in nodes_tuple if n.touches_management_plane}
        node_set = set(nodes)
        succ: dict[str, set[str]] = {nid: set() for nid in nodes}
        indeg: dict[str, int] = {nid: 0 for nid in nodes}
        for src, dst, _reason in edges:
            if src in node_set and dst in node_set and dst not in succ[src]:
                succ[src].add(dst)
                indeg[dst] += 1

        def frontier_key(nid: str) -> tuple[int, str]:
            return (0 if nid in mgmt else 1, nid)

        ready = sorted([n for n in nodes if indeg[n] == 0], key=frontier_key)
        order: list[str] = []
        while ready:
            current = ready.pop(0)
            order.append(current)
            for nxt in sorted(succ[current]):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    ready.append(nxt)
            ready.sort(key=frontier_key)

        if len(order) != len(nodes):
            cyclic = sorted(n for n in nodes if indeg[n] > 0)
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"DEPENDENCY_CYCLE: no total order exists; nodes in cycle: {cyclic}",))

        natural = sorted(nodes)
        mgmt_first_applied = any(
            order.index(m) < order.index(n) and natural.index(m) > natural.index(n)
            for m in mgmt for n in nodes if n not in mgmt
        )
        return order, mgmt_first_applied
