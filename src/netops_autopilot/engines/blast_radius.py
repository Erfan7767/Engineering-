"""E13 Blast Radius Engine — DECIDE risk class (D0-02, FSM-2 2.3).

Answers, before execution: if this change misbehaves, what is affected?
Three propagation channels, each honest about its limits:
1. IR-internal graph — nodes sharing targets or requires/provides tokens;
   fixed-point traversal (a changed token affects requirers, whose own
   targets and provided tokens are then affected too);
2. service graph — P1-34 dependents of any touched service;
3. twin links — ONLY if link endpoints are modeled; today a twin LINK
   carries evidence state but no endpoint fields, so link propagation is
   reported as an explicit GAP (D0-08 §5 philosophy), never faked.

Risk class vocabulary reuses the gate classes (deterministic worst-case):
LOW_RISK < HIGH_RISK < IRREVERSIBLE < DESTRUCTIVE. Blast size escalates
LOW_RISK to HIGH_RISK past an absolute threshold (constructor parameter —
a policy fact, not a percentage, T3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..twin.twin import DigitalTwin
from .config_ir import ConfigIR, EntityRef
from .service_graph import ServiceGraph
from .validation_fabric import MGMT_FEATURES

RISK_ORDER = ("LOW_RISK", "HIGH_RISK", "IRREVERSIBLE", "DESTRUCTIVE")

#: Twin link endpoint predicates; absent ⇒ link propagation NOT_MODELED.
LINK_ENDPOINT_FIELDS = ("a_endpoint", "z_endpoint")


@dataclass(frozen=True)
class BlastReport:
    ir_id: str
    risk_class: str
    directly_affected: tuple[EntityRef, ...]
    internal_affected_nodes: tuple[str, ...]  # nodes hit by propagation, sorted
    affected_services: tuple[str, ...]        # service-graph dependents, sorted
    management_plane_touched: bool
    gaps: tuple[str, ...]
    worst_case: str


class BlastRadiusEngine:
    def __init__(self, twin: Optional[DigitalTwin] = None,
                 service_graph: Optional[ServiceGraph] = None,
                 escalation_threshold: int = 5) -> None:
        self._twin = twin
        self._services = service_graph
        self._threshold = escalation_threshold

    # --------------------------------------------------------------- evaluate
    def evaluate(self, ir: ConfigIR) -> BlastReport:
        affected_nodes = self._propagate(ir)
        direct = self._direct_entities(ir)
        services = self._affected_services(ir, affected_nodes)
        mgmt_touched = self._mgmt_touched(ir, affected_nodes)
        gaps = self._link_gaps()

        risk = ir.gate_class()
        blast_size = len(direct) + len(affected_nodes)
        if risk == "LOW_RISK" and blast_size > self._threshold:
            risk = "HIGH_RISK"

        worst = (f"blast touches {len(direct)} entit(y/ies) and "
                 f"{len(affected_nodes)} downstream IR node(s); "
                 f"{len(services)} dependent service(s); "
                 f"mgmt-plane {'TOUCHED' if mgmt_touched else 'not touched'}")
        return BlastReport(ir_id=ir.ir_id, risk_class=risk,
                           directly_affected=direct,
                           internal_affected_nodes=tuple(affected_nodes),
                           affected_services=services,
                           management_plane_touched=mgmt_touched,
                           gaps=gaps, worst_case=worst)

    # -------------------------------------------------------------- channels
    def _direct_entities(self, ir: ConfigIR) -> tuple[EntityRef, ...]:
        return tuple(sorted({n.target for n in ir.nodes},
                            key=lambda e: (e.entity_type, e.entity_ref)))

    def _propagate(self, ir: ConfigIR) -> list[str]:
        """Fixed-point propagation over tokens and shared targets. Returns
        affected node ids EXCLUDING the directly changed nodes, sorted."""
        nodes = list(ir.nodes)
        changed = {n.node_id for n in nodes}  # all IR nodes are changed by definition
        hot_tokens: set[str] = set()
        hot_entities: set[EntityRef] = set()
        for node in nodes:
            hot_tokens.update(node.provides)
            hot_tokens.add(node.feature)
            hot_entities.add(node.target)

        affected: set[str] = set()
        progressed = True
        while progressed:
            progressed = False
            for node in nodes:
                if node.node_id in changed or node.node_id in affected:
                    continue
                hit = (bool(set(node.requires) & hot_tokens)
                       or node.target in hot_entities
                       or bool(set(node.conflicts) & hot_tokens)
                       or bool(set(node.blocks) & hot_tokens))
                if hit:
                    affected.add(node.node_id)
                    hot_tokens.update(node.provides)
                    hot_tokens.add(node.feature)
                    hot_entities.add(node.target)
                    progressed = True
        return sorted(affected)

    def _affected_services(self, ir: ConfigIR, affected_nodes: list[str]) -> tuple[str, ...]:
        if self._services is None:
            return ()
        touched: set[str] = set()
        features = {n.feature for n in ir.nodes}
        for feature in sorted(features):
            if feature in self._services.names():
                touched.update(self._services.dependents_of(feature))
        return tuple(sorted(touched))

    @staticmethod
    def _mgmt_touched(ir: ConfigIR, affected_nodes: list[str]) -> bool:
        by_id = {n.node_id: n for n in ir.nodes}
        for node in ir.nodes:
            if node.touches_management_plane or node.feature in MGMT_FEATURES:
                return True
        for nid in affected_nodes:
            node = by_id.get(nid)
            if node and (node.touches_management_plane or node.feature in MGMT_FEATURES):
                return True
        return False

    def _link_gaps(self) -> tuple[str, ...]:
        """Twin links without endpoint fields cannot propagate blast — say so."""
        if self._twin is None:
            return ()
        links = self._twin.links()
        for link in links:
            if not all(pred in link.fields for pred in LINK_ENDPOINT_FIELDS):
                return ("LINK_ENDPOINTS_NOT_MODELED",)
        return ()
