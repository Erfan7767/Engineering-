"""Claim/Relevance Verifier (D4) — the Relevance Guard of D0-04 §5 (T1).

A Claim's ``evidence_ids`` must satisfy ALL THREE rules, checked per
evidence item, fail-closed and fully reported:

1. SAME DEVICE — the evidence chain (Observation → RawArtifact → Event)
   must originate on the claimed device; for non-DEVICE subjects every
   evidence item must at least share one consistent origin device;
2. SAME COMMAND/OPERATION — the Event's ``command_or_op`` must equal the
   producing parser's ``command_ref`` (the command→field registry per
   vendor/version), and the Observation must be OF the claimed field;
3. PARSED — the Observation's ``parse_status`` must be OK (L01: a MISSING
   or PARSE_FAILED observation proves nothing about a value).

Additionally, superseded observations carry no relevance (re-parse
produces new observations; the old ones are dead). Existence of *some*
evidence is not relevance — the verdict lists every violated rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Claim, ParseStatus
from .store import LedgerStore
from ..parsers.registry import ParserRegistry


@dataclass(frozen=True)
class RelevanceVerdict:
    admitted: bool
    relevance_check: str  # "PASS" | "FAIL"
    reasons: tuple[str, ...]


class ClaimVerifier:
    def __init__(self, store: LedgerStore, registry: ParserRegistry) -> None:
        self._observations = {o.obs_id: o for o in store.observations()}
        self._artifacts = {a.raw_id: a for a in store.raw_artifacts()}
        self._events = {e.event_id: e for e in store.events()}
        self._registry = registry

    # ------------------------------------------------------------------ verify
    def verify(self, claim: Claim) -> RelevanceVerdict:
        reasons: list[str] = []
        origins: set[str] = set()

        for evidence_id in sorted(set(claim.evidence_ids)):
            observation = self._observations.get(evidence_id)
            if observation is None:
                reasons.append(f"EVIDENCE_UNKNOWN:{evidence_id}")
                continue
            if observation.superseded_by is not None:
                reasons.append(f"EVIDENCE_SUPERSEDED:{evidence_id}")
                continue

            # Rule 3: the field must actually be parsed (L01).
            if observation.parse_status is not ParseStatus.OK:
                reasons.append(f"EVIDENCE_NOT_PARSED:{evidence_id}:{observation.parse_status.value}")
                continue
            if observation.field != claim.predicate:
                reasons.append(f"EVIDENCE_FIELD_MISMATCH:{evidence_id}:{observation.field}!={claim.predicate}")
                continue

            artifact = self._artifacts.get(observation.raw_id)
            event = self._events.get(artifact.event_id) if artifact else None
            if artifact is None or event is None:
                reasons.append(f"EVIDENCE_CHAIN_BROKEN:{evidence_id}")
                continue
            if event.device_id:
                origins.add(event.device_id)

            # Rule 2: command→field registry agreement.
            try:
                parser = self._registry.get(observation.parser_id, observation.parser_version)
            except KeyError:
                reasons.append(f"PARSER_UNKNOWN:{observation.parser_id}@{observation.parser_version}")
                continue
            if event.command_or_op != parser.info.command_ref:
                reasons.append(f"COMMAND_REGISTRY_MISMATCH:{evidence_id}:"
                               f"{event.command_or_op}!={parser.info.command_ref}")
                continue

            # Rule 1: same device.
            if claim.subject_entity.entity_type == "DEVICE":
                if event.device_id != claim.subject_entity.entity_ref:
                    reasons.append(f"DEVICE_MISMATCH:{evidence_id}:{event.device_id}"
                                   f"!=claimed {claim.subject_entity.entity_ref}")
            # Non-DEVICE subjects: consistent single origin enforced below.

        if claim.subject_entity.entity_type != "DEVICE" and len(origins) > 1:
            reasons.append(f"CROSS_DEVICE_EVIDENCE_UNDECLARED:{sorted(origins)}")

        admitted = not reasons
        return RelevanceVerdict(admitted=admitted,
                                relevance_check="PASS" if admitted else "FAIL",
                                reasons=tuple(sorted(reasons)))
