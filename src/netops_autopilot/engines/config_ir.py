"""E09 Config IR — the vendor-neutral intermediate representation (§12).

P0-18 rules realized here:
* every node carries an explicit reversibility tag — no tag, no node;
* IRREVERSIBLE nodes must justify themselves (``irreversibility_reason``);
* nodes declare requires/provides/conflicts/blocks/depends_on — this is the
  exact input of the Dependency DAG (E12) and Blast Radius (E13) in D3;
* management-plane contact is a first-class flag (L15 downstream).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from ..core.failures import Failure, FailureClass
from ..core.ids import new_id


class Reversibility(str, Enum):
    REVERSIBLE_BY_REPLACE = "REVERSIBLE_BY_REPLACE"
    REVERSIBLE_MANUAL = "REVERSIBLE_MANUAL"
    IRREVERSIBLE = "IRREVERSIBLE"


#: Ordered from most to least reversible (used for gate classification).
REVERSIBILITY_SEVERITY = (
    Reversibility.REVERSIBLE_BY_REPLACE,
    Reversibility.REVERSIBLE_MANUAL,
    Reversibility.IRREVERSIBLE,
)


class Operation(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


#: Features that constitute destructive recovery actions (§9). They can only
#: ride a Change through the DESTRUCTIVE gate with a human decision.
DESTRUCTIVE_FEATURES = frozenset({
    "netinstall", "rommon_reset", "factory_reset", "bootloader_recovery",
})

#: Management-plane feature vocabulary (§13/§14 gate escalation input).
#: Frozen — grows only through a register-recorded spec change.
MGMT_FEATURES = frozenset({"ssh_mgmt", "aaa_radius", "mgmt_ip", "oob", "console"})


@dataclass(frozen=True)
class EntityRef:
    entity_type: str
    entity_ref: str

    def __post_init__(self) -> None:
        if not self.entity_type or not self.entity_ref:
            raise Failure(cls=FailureClass.BLOCKED, causes=("IR_ENTITY_REF_EMPTY: entity_type/entity_ref required",))


@dataclass(frozen=True)
class IRNode:
    """One desired-state operation on one entity."""

    node_id: str
    target: EntityRef
    operation: Operation
    feature: str
    vendor_os: str
    parameters: Mapping[str, object]
    reversibility: Reversibility
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    blocks: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    touches_management_plane: bool = False

    @property
    def destructive(self) -> bool:
        return self.feature in DESTRUCTIVE_FEATURES or bool(self.parameters.get("destructive", False))

    def is_well_formed(self) -> list[str]:
        """Structural self-check; empty list = well-formed."""
        problems: list[str] = []
        if not self.node_id:
            problems.append("node_id empty")
        if not self.feature:
            problems.append("feature empty")
        if not self.vendor_os:
            problems.append("vendor_os empty")
        if not isinstance(self.parameters, Mapping):
            problems.append("parameters must be a mapping")
        else:
            for key in self.parameters:
                if not isinstance(key, str) or not key:
                    problems.append(f"parameter key must be non-empty str: {key!r}")
        for token_list, name in ((self.requires, "requires"), (self.provides, "provides"),
                                 (self.conflicts, "conflicts"), (self.blocks, "blocks")):
            for token in token_list:
                if ":" not in token:
                    problems.append(f"{name} token missing 'class:name' shape: {token!r}")
        if self.reversibility is Reversibility.IRREVERSIBLE:
            reason = self.parameters.get("irreversibility_reason")
            if not (isinstance(reason, str) and reason.strip()):
                problems.append("IRREVERSIBLE node requires parameters['irreversibility_reason'] (P0-18)")
        if self.operation is Operation.DELETE and self.parameters.get("vlan_id") is not None:
            pass  # DELETE validity is semantic-stage business
        return problems


@dataclass(frozen=True)
class ConfigIR:
    """A full desired-state change in IR form."""

    title: str
    nodes: tuple[IRNode, ...]
    ir_id: str = field(default_factory=new_id)

    def __post_init__(self) -> None:
        if not self.title:
            raise Failure(cls=FailureClass.BLOCKED, causes=("IR_TITLE_EMPTY",))
        if not self.nodes:
            raise Failure(cls=FailureClass.BLOCKED, causes=("IR_EMPTY: an IR without nodes is not a change",))
        seen: set[str] = set()
        for node in self.nodes:
            if node.node_id in seen:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"IR_DUPLICATE_NODE_ID: {node.node_id}",))
            seen.add(node.node_id)

    # -------------------------------------------------------------- queries
    def node(self, node_id: str) -> IRNode:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        raise KeyError(node_id)

    def max_reversibility(self) -> Reversibility:
        """Worst-case reversibility across all nodes (gate input)."""
        worst = REVERSIBILITY_SEVERITY[0]
        for node in self.nodes:
            if REVERSIBILITY_SEVERITY.index(node.reversibility) > REVERSIBILITY_SEVERITY.index(worst):
                worst = node.reversibility
        return worst

    def contains_destructive(self) -> bool:
        return any(node.destructive for node in self.nodes)

    def touches_management_plane(self) -> bool:
        """Explicit flag OR membership in the frozen MGMT_FEATURES list —
        known management-plane contact is HIGH_RISK even when the planner
        forgot the flag (deterministic data-driven escalation, no guessing)."""
        return any(node.touches_management_plane or node.feature in MGMT_FEATURES
                   for node in self.nodes)

    def gate_class(self) -> str:
        """Deterministic §13 gate-class derivation from IR content alone."""
        if self.contains_destructive():
            return "DESTRUCTIVE"
        if self.max_reversibility() is Reversibility.IRREVERSIBLE:
            return "IRREVERSIBLE"
        if self.touches_management_plane():
            return "HIGH_RISK"
        return "LOW_RISK"
