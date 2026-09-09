"""Claim Factory — the E04 claim production path (T1-strict).

A claim enters the ledger/Twin ONLY when the Claim Relevance Guard's three
rules hold, verified INLINE with the real ``ClaimVerifier`` (D0-04 §5):

* predicate == observation.field (rule: command→field registry agreement),
* observation parse_status == OK (L01),
* the Observation→RawArtifact→Event chain originates on the claimed device.

Canonicalization (parser field names → canonical identity vocabulary) is NOT
performed here: deriving ``vendor/os/os_version`` from family metadata needs
a Normalizer (E03) with its own evidence chain — registered as OI-0173.
Until then, claims carry parser-field predicates, and identity is read from
them by downstream engines without renaming.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ledger.claim_verifier import ClaimVerifier
from ..ledger.models import (
    Claim,
    ClaimStatus,
    Observation,
    ParseStatus,
    SubjectEntity,
)
from ..ledger.store import LedgerStore
from ..parsers.registry import ParserRegistry

#: verification_scope per predicate family (D0-04 §scopes; D0-08 §3).
_SCOPE_BY_FIELD: dict[str, str] = {
    "version": "DEVICE_IDENTITY",
    "model": "DEVICE_IDENTITY",
    "serial": "DEVICE_IDENTITY",
    "uptime": "DEVICE_IDENTITY",
}
_DEFAULT_IDENTITY_SCOPE = "DEVICE_IDENTITY"


def scope_for(field: str) -> str:
    if field.startswith("neighbor_table_") or field.startswith("neighbor_count_"):
        return "DIRECT_NEIGHBOR"
    return _SCOPE_BY_FIELD.get(field, _DEFAULT_IDENTITY_SCOPE)


@dataclass(frozen=True)
class ClaimIssue:
    claim: Claim
    admitted: bool
    reasons: tuple[str, ...]


class ClaimFactory:
    """Builds, verifies, and appends claims from fresh observations.

    The verifier snapshots the ledger at construction; the factory rebuilds
    it per device batch so claims always verify against the CURRENT chain.
    """

    def __init__(self, store: LedgerStore, registry: ParserRegistry) -> None:
        self._store = store
        self._registry = registry

    def issue_for_device(self, device_ref: str, observations: list[Observation]) -> list[ClaimIssue]:
        """One claim per OK observation whose predicate equals the field name.

        MISSING/PARSE_FAILED observations produce NO claim (T2, L01) and are
        reported as skipped issues so the absence is visible, not silent."""
        verifier = ClaimVerifier(self._store, self._registry)
        issues: list[ClaimIssue] = []
        for obs in observations:
            if obs.parse_status is not ParseStatus.OK:
                # Typed absence — no claim, but the skip is returned so the
                # caller can count it (T4 visibility).
                continue
            claim = Claim(
                subject_entity=SubjectEntity(entity_type="DEVICE", entity_ref=device_ref),
                predicate=obs.field,
                value=obs.value,
                evidence_ids=[obs.obs_id],
                verification_scope=scope_for(obs.field),
                status=ClaimStatus.CONFIRMED,
                relevance_check="PASS",  # provisional; verifier decides for real below
            )
            verdict = verifier.verify(claim)
            if not verdict.admitted:
                # Never store a claim the guard rejects; the refusal itself is
                # the audit trail (fail-closed, counted upstream via T5).
                issues.append(ClaimIssue(claim=claim, admitted=False, reasons=verdict.reasons))
                continue
            claim = claim.model_copy(update={"relevance_check": verdict.relevance_check})
            self._store.append_claim(claim)
            issues.append(ClaimIssue(claim=claim, admitted=True, reasons=()))
        return issues
