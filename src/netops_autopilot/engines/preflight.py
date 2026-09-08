"""E11 Preflight Engine — "is this IR modeled for these devices?" (§13).

This engine answers ONE question per IR, before anything touches a device:
do we have a deterministic execution model for every node? It is the
supplier of the ``PreflightFn`` contract consumed by the Validation Fabric's
PREFLIGHT stage.

Honesty rules:
* a node whose target entity is absent from the Twin cannot be modeled
  (MODEL_INCOMPLETE — the ENTITY_GUARD stage owns the BLOCKED verdict);
* no adapter registered for the resolved (vendor, os, model) ⇒ NOT_MODELED
  per node, and NOT_MODELED dominates the aggregate (L13: NOT_MODELED is
  never rewritten into PASS);
* adapter present but the mechanical capability is UNKNOWN ⇒ PARTIALLY_MODELED
  (the adapter exists, it does not claim the operation — no guessing, T2);
* a declared ``node.vendor_os`` contradicting the Twin's evidenced identity
  is a modeling gap, not a judgment call ⇒ MODEL_INCOMPLETE;
* zero I/O: preflight never opens sessions; capability answers come from
  registered adapter metadata only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..adapters.interfaces import AdapterBase, CapabilityState
from ..adapters.registry import AdapterRegistry
from ..twin.models import DEVICE_IDENTITY_FIELDS
from ..twin.twin import DigitalTwin
from .config_ir import ConfigIR, IRNode
from .validation_fabric import PreflightStatus

#: Per-node modeling contribution, ordered worst-first for aggregation.
_NODE_STATES = ("NOT_MODELED", "MODEL_INCOMPLETE", "PARTIALLY_MODELED", "MODELED")


@dataclass(frozen=True)
class NodeAssessment:
    node_id: str
    state: str  # one of _NODE_STATES
    code: str   # typed reason: NO_ADAPTER | ENTITY_ABSENT | IDENTITY_INCOMPLETE |
                # VENDOR_OS_MISMATCH | CAPABILITY_UNKNOWN | CAPABILITY_NOT_SUPPORTED | MODELED


class PreflightEngine:
    """Deterministic IR-vs-model assessment. Satisfies ``PreflightFn`` via
    :meth:`evaluate` (bound method has signature ``ir → PreflightStatus``)."""

    def __init__(self, registry: AdapterRegistry, twin: DigitalTwin) -> None:
        self._registry = registry
        self._twin = twin

    # ------------------------------------------------------------ aggregate
    def evaluate(self, ir: ConfigIR) -> PreflightStatus:
        assessments = tuple(self._assess(node) for node in ir.nodes)
        aggregate = self._aggregate(a.state for a in assessments)
        notes = "; ".join(f"{a.node_id}={a.state}:{a.code}" for a in assessments)
        return PreflightStatus(state=aggregate, notes=notes)

    def assess_nodes(self, ir: ConfigIR) -> tuple[NodeAssessment, ...]:
        """Per-node detail, in IR order (deterministic)."""
        return tuple(self._assess(node) for node in ir.nodes)

    # ------------------------------------------------------------- internal
    @staticmethod
    def _aggregate(states) -> str:
        """Worst-first: NOT_MODELED > MODEL_INCOMPLETE > PARTIALLY_MODELED.
        Aggregate values use the ``PreflightStatus`` vocabulary exactly."""
        present = set(states)
        for state in _NODE_STATES:
            if state in present:
                return "SUPPORTED_AND_MODELED" if state == "MODELED" else state
        return "NOT_MODELED"  # empty input cannot claim to be modeled

    def _assess(self, node: IRNode) -> NodeAssessment:
        entity = self._twin.entity(node.target.entity_type, node.target.entity_ref)
        if entity is None:
            return NodeAssessment(node.node_id, "MODEL_INCOMPLETE", "ENTITY_ABSENT")

        identity = {pred: entity.fields[pred].value
                    for pred in DEVICE_IDENTITY_FIELDS if pred in entity.fields}
        vendor = identity.get("vendor")
        os_name = identity.get("os")
        if not vendor or vendor == "UNKNOWN" or not os_name or os_name == "UNKNOWN":
            return NodeAssessment(node.node_id, "MODEL_INCOMPLETE", "IDENTITY_INCOMPLETE")

        declared = node.vendor_os.strip().lower()
        evidenced = f"{vendor}/{os_name}".strip().lower()
        if declared and declared != evidenced:
            return NodeAssessment(node.node_id, "MODEL_INCOMPLETE", "VENDOR_OS_MISMATCH")

        adapter: Optional[object] = self._registry.resolve(
            vendor=str(vendor), os=str(os_name), model=identity.get("model"))
        if adapter is None:
            return NodeAssessment(node.node_id, "NOT_MODELED", "NO_ADAPTER")

        operation = f"{node.operation.value}:{node.feature}"
        capability = adapter.capability(operation) if isinstance(adapter, AdapterBase) else CapabilityState.UNKNOWN
        if capability is CapabilityState.SUPPORTED:
            return NodeAssessment(node.node_id, "MODELED", "MODELED")
        if capability is CapabilityState.NOT_SUPPORTED:
            return NodeAssessment(node.node_id, "MODEL_INCOMPLETE", "CAPABILITY_NOT_SUPPORTED")
        return NodeAssessment(node.node_id, "PARTIALLY_MODELED", "CAPABILITY_UNKNOWN")
