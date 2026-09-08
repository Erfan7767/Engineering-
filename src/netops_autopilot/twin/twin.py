"""E05 Digital Twin engine — claims in, typed projection out.

Admission rules (fail-closed, evidence-only):
* Only Claims with ``status=CONFIRMED`` mutate the Twin.
* Only Claims with ``relevance_check=PASS`` mutate the Twin (T1); applying
  an irrelevant claim is a counted violation (``unverified_claims``).
* Entity Guard (L02 + §5): the Twin creates entities from OBSERVED claims
  (evidence-driven). Fabrication risk lives at the agent boundary: agents
  may only reference entities that already exist here (D4 Entity Guard).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterator, Optional

from ..core.counters import CounterCollector
from ..core.failures import Failure, FailureClass
from ..ledger.models import Claim, ClaimStatus, OperatorIdentity, StateTransition
from ..ledger.store import LedgerStore
from .models import (
    DEVICE_IDENTITY_FIELDS,
    LINK_GAP_STATES,
    EntityState,
    FieldRecord,
    layer_for,
)

TWIN_FSM_LABEL = "TWIN_PROJECTION"
ENGINE_ACTOR = OperatorIdentity(kind="ENGINE", id="E05")


class Admission(str, Enum):
    APPLIED = "APPLIED"
    REJECTED_NOT_CONFIRMED = "REJECTED_NOT_CONFIRMED"
    REJECTED_NOT_RELEVANT = "REJECTED_NOT_RELEVANT"


@dataclass(frozen=True)
class ApplyResult:
    admission: Admission
    entity_key: tuple[str, str]
    predicate: str
    reason: str


@dataclass(frozen=True)
class Gap:
    """An explicit model incompleteness (D0-08 §5 Gaps List)."""

    kind: str
    entity_type: str
    entity_ref: str
    detail: str


class DigitalTwin:
    """Current-state projection with full evidence provenance."""

    def __init__(self, store: LedgerStore, counters: CounterCollector) -> None:
        self._store = store
        self._counters = counters
        self._entities: dict[tuple[str, str], EntityState] = {}

    # ------------------------------------------------------------- mutation
    def apply_claim(self, claim: Claim, collected_at: datetime, actor: OperatorIdentity = ENGINE_ACTOR) -> ApplyResult:
        """Admit one claim into the projection. Never raises on bad claims —
        admission is a typed verdict (L03): the caller learns exactly why."""
        key = (claim.subject_entity.entity_type, claim.subject_entity.entity_ref)

        if claim.relevance_check != "PASS":
            self._counters.increment(
                "unverified_claims",
                f"IRRELEVANT_CLAIM_APPLIED: claim={claim.claim_id} subject={key[1]} predicate={claim.predicate}",
            )
            return ApplyResult(Admission.REJECTED_NOT_RELEVANT, key, claim.predicate,
                               "relevance_check != PASS (T1 Relevance Guard)")

        if claim.status is not ClaimStatus.CONFIRMED:
            return ApplyResult(Admission.REJECTED_NOT_CONFIRMED, key, claim.predicate,
                               f"claim status is {claim.status.value}; only CONFIRMED mutates the Twin")

        entity = self._entities.get(key)
        if entity is None:
            entity = EntityState(entity_type=key[0], entity_ref=key[1], created_at=collected_at)
            self._entities[key] = entity

        layer, origin = layer_for(claim.predicate)
        entity.fields[claim.predicate] = FieldRecord(
            value=claim.value,
            evidence_ids=tuple(claim.evidence_ids),
            layer=layer,
            layer_origin=origin,
            updated_at=collected_at,
        )

        # Every mutation is a ledger record (D0-04 chain tail; L08).
        self._store.append_transition(StateTransition(
            fsm=TWIN_FSM_LABEL,
            entity_ref=f"{key[0]}:{key[1]}",
            from_state=f"field:{claim.predicate}:ABSENT" if claim.predicate not in entity.fields else f"field:{claim.predicate}:PRESENT",
            to_state=f"field:{claim.predicate}:UPDATED",
            guard_id="TWIN-ADMIT",
            evidence_ids=list(claim.evidence_ids),
            actor=actor,
            collected_at=collected_at,
        ))
        return ApplyResult(Admission.APPLIED, key, claim.predicate, "APPLIED")

    # -------------------------------------------------------------- queries
    def entity(self, entity_type: str, entity_ref: str) -> Optional[EntityState]:
        return self._entities.get((entity_type, entity_ref))

    def entities(self, entity_type: Optional[str] = None) -> list[EntityState]:
        out = [e for e in self._entities.values() if entity_type is None or e.entity_type == entity_type]
        return sorted(out, key=lambda e: e.entity_ref)

    def exists(self, entity_type: str, entity_ref: str) -> bool:
        """Entity Guard lookup for the agent boundary (§5, D4)."""
        return (entity_type, entity_ref) in self._entities

    def links(self) -> list[EntityState]:
        return self.entities("LINK")

    # ----------------------------------------------------------------- gaps
    def gaps(self) -> list[Gap]:
        """Explicit Gaps List (D0-08 §5): everything the model does not yet
        know, typed. Rendered wherever the model is displayed (L14)."""
        out: list[Gap] = []
        for entity in self.entities("DEVICE"):
            missing = [f for f in DEVICE_IDENTITY_FIELDS if f not in entity.fields]
            if missing:
                out.append(Gap("IDENTITY_INCOMPLETE", entity.entity_type, entity.entity_ref,
                               "missing fields: " + ", ".join(missing)))
        for entity in self.entities("INTERFACE"):
            if "oper_status" not in entity.fields:
                out.append(Gap("FIELD_UNKNOWN", entity.entity_type, entity.entity_ref,
                               "oper_status unknown (no confirmed evidence)"))
        for link in self.links():
            state_field = link.fields.get("link_state")
            state = str(state_field.value) if state_field else "UNKNOWN"
            if state in LINK_GAP_STATES:
                out.append(Gap("LINK_EVIDENCE_BELOW_CONFIRMED", link.entity_type, link.entity_ref,
                               f"FSM-4 state={state}"))
        return sorted(out, key=lambda g: (g.kind, g.entity_ref))
