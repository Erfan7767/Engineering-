"""Twin entity model (D0-08 §4–§5).

Layers: Physical | Logical | Operational | Intent | Security | Dependency |
Service | Historical. Every field carries the evidence ids that justify it
and the layer it belongs to; unknown predicates fall back to OPERATIONAL
with ``layer_origin="default"`` so the fallback itself is explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TwinLayer(str, Enum):
    PHYSICAL = "PHYSICAL"
    LOGICAL = "LOGICAL"
    OPERATIONAL = "OPERATIONAL"
    INTENT = "INTENT"
    SECURITY = "SECURITY"
    DEPENDENCY = "DEPENDENCY"
    SERVICE = "SERVICE"
    HISTORICAL = "HISTORICAL"


#: Predicate → layer registry (grown with evidence; D0-08 §5).
PREDICATE_LAYERS: dict[str, TwinLayer] = {
    # identity / hardware → Physical
    "vendor": TwinLayer.PHYSICAL,
    "model": TwinLayer.PHYSICAL,
    "os": TwinLayer.PHYSICAL,
    "os_version": TwinLayer.PHYSICAL,
    "serial": TwinLayer.PHYSICAL,
    "hw_serial": TwinLayer.PHYSICAL,
    "fw_version": TwinLayer.PHYSICAL,
    "bootloader_version": TwinLayer.PHYSICAL,
    "psu_state": TwinLayer.PHYSICAL,
    "fan_state": TwinLayer.PHYSICAL,
    # interface state → Operational / Logical
    "admin_status": TwinLayer.OPERATIONAL,
    "oper_status": TwinLayer.OPERATIONAL,
    "mac_address": TwinLayer.OPERATIONAL,
    "speed": TwinLayer.OPERATIONAL,
    "duplex": TwinLayer.OPERATIONAL,
    "counters": TwinLayer.OPERATIONAL,
    "mtu": TwinLayer.LOGICAL,
    "native_vlan": TwinLayer.LOGICAL,
    "allowed_vlans": TwinLayer.LOGICAL,
    "port_mode": TwinLayer.LOGICAL,
    "ipv4_address": TwinLayer.LOGICAL,
    "ipv6_address": TwinLayer.LOGICAL,
    # topology → Dependency
    "neighbor_is": TwinLayer.DEPENDENCY,
    "link_state": TwinLayer.DEPENDENCY,
}


def layer_for(predicate: str) -> tuple[TwinLayer, str]:
    """Return (layer, origin): 'registry' for known predicates,
    'default' (OPERATIONAL) otherwise — the fallback is explicit."""
    if predicate in PREDICATE_LAYERS:
        return PREDICATE_LAYERS[predicate], "registry"
    return TwinLayer.OPERATIONAL, "default"


@dataclass
class FieldRecord:
    """One field of one entity, with its justifying evidence."""

    value: object
    evidence_ids: tuple[str, ...]
    layer: TwinLayer
    layer_origin: str  # "registry" | "default"
    updated_at: datetime


@dataclass
class EntityState:
    """A Twin entity. ``fields`` maps predicate → FieldRecord."""

    entity_type: str
    entity_ref: str
    fields: dict[str, FieldRecord] = field(default_factory=dict)
    created_at: datetime | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.entity_type, self.entity_ref)

    def layers_present(self) -> list[TwinLayer]:
        return sorted({fr.layer for fr in self.fields.values()}, key=lambda l: l.value)


#: Identity fields a DEVICE must eventually hold (FSM-1 guard 1.3 set).
DEVICE_IDENTITY_FIELDS: tuple[str, ...] = ("vendor", "model", "os", "os_version")

#: FSM-4 states that still represent an evidence gap (below CONFIRMED).
LINK_GAP_STATES: frozenset[str] = frozenset({
    "UNKNOWN", "INFERRED", "ONE_SIDED", "CONFLICTING",
    "INTERMEDIATE_SUSPECTED", "STALE",
})
