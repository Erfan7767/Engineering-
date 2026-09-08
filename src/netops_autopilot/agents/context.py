"""Agent Context Builder (D4, L11) — facts in, secrets out.

Assembles the factual context an agent may see (Twin fields for the
referenced entities) while EXCLUDING every secret-bearing predicate.
Redactions are recorded explicitly — the agent's prompt shows that a
field exists but is withheld, never a value, never a guess (L01).

Deterministic: entities and fields are emitted in sorted order; the same
Twin state always yields the same context.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..twin.twin import DigitalTwin

#: Secret-bearing predicates. Membership is the ONLY criterion — no value
#: inspection, no heuristics on content (values are evidence, not ours to
#: reinterpret). Frozen; grows only through a register-recorded change.
SECRET_PREDICATES = frozenset({
    "password", "password_hash", "secret", "shared_secret",
    "api_key", "api_token", "access_token", "private_key",
    "snmp_community", "credential_ref", "vault_ref",
})


@dataclass(frozen=True)
class ContextField:
    entity_type: str
    entity_ref: str
    predicate: str
    value: object
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class Redaction:
    entity_type: str
    entity_ref: str
    predicate: str


@dataclass(frozen=True)
class AgentContext:
    facts: tuple[ContextField, ...]
    redactions: tuple[Redaction, ...]

    def has_secret_leak(self) -> bool:
        """Self-check (defense in depth): no secret predicate may ever
        appear in the emitted facts."""
        return any(f.predicate in SECRET_PREDICATES for f in self.facts)


def build_context(twin: DigitalTwin,
                  entity_refs: tuple[tuple[str, str], ...]) -> AgentContext:
    facts: list[ContextField] = []
    redactions: list[Redaction] = []
    for entity_type, entity_ref in sorted(set(entity_refs)):
        entity = twin.entity(entity_type, entity_ref)
        if entity is None:
            continue  # absent entities produce no facts — never invented (L01)
        for predicate in sorted(entity.fields):
            record = entity.fields[predicate]
            if predicate in SECRET_PREDICATES:
                redactions.append(Redaction(entity_type, entity_ref, predicate))
                continue
            facts.append(ContextField(entity_type=entity_type, entity_ref=entity_ref,
                                      predicate=predicate, value=record.value,
                                      evidence_ids=tuple(record.evidence_ids)))
    return AgentContext(facts=tuple(facts), redactions=tuple(redactions))
