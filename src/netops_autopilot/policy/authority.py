"""Authority Model (D0-02) compiled from ``specs/data/authority_table.json``.

Invariants enforced at import time and by unit tests:
* exactly one DECIDE cell per decision (or a documented co-decide pair),
* no LLM agent in any DECIDE/VETO cell,
* the HUMAN_ONLY set is frozen and cannot be mutated here or by policies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Union

#: L06 frozen constant (docs/D0/01 §2). Not removable by any policy.
HUMAN_ONLY: frozenset[str] = frozenset(
    {"IRREVERSIBLE", "DESTRUCTIVE", "MANAGEMENT_PATH_TOUCHING", "NOT_MODELED_HIGH_RISK"}
)

_LLM_AGENTS = {"A1_ORCHESTRATOR", "A2_REQUIREMENTS", "A3_ARCHITECT", "A4_AUDITOR", "A5_TROUBLESHOOTER"}


@dataclass(frozen=True)
class AuthorityCell:
    decision: str
    propose: tuple[str, ...]
    decide: tuple[str, ...]
    veto: tuple[str, ...]


def _load_table() -> list[AuthorityCell]:
    raw = resources.files("netops_autopilot.policy").joinpath("data/authority_table.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    cells = []
    for row in data["decisions"]:
        decide = row["decide"] if isinstance(row["decide"], list) else [row["decide"]]
        cells.append(
            AuthorityCell(
                decision=row["decision"],
                propose=tuple(row["propose"]),
                decide=tuple(decide),
                veto=tuple(row["veto"]),
            )
        )
    return cells


AUTHORITY_TABLE: tuple[AuthorityCell, ...] = tuple(_load_table())


class AuthorityViolation(RuntimeError):
    """Raised when the authority invariants are broken (build error)."""


def assert_authority_invariants() -> None:
    """Validate the table against D0-02 binding rules. Raises AuthorityViolation."""
    seen: set[str] = set()
    for cell in AUTHORITY_TABLE:
        if cell.decision in seen:
            raise AuthorityViolation(f"duplicate decision row: {cell.decision}")
        seen.add(cell.decision)
        if not cell.decide:
            raise AuthorityViolation(f"decision without DECIDE cell: {cell.decision}")
        for actor in cell.decide:
            if actor in _LLM_AGENTS:
                raise AuthorityViolation(f"LLM agent in DECIDE cell: {cell.decision}/{actor}")
        for actor in cell.veto:
            # A4 (Auditor) may VETO per spec §4; no other LLM agent may.
            if actor in _LLM_AGENTS and actor != "A4_AUDITOR":
                raise AuthorityViolation(f"non-auditor LLM agent in VETO cell: {cell.decision}/{actor}")
        if set(cell.propose) & set(cell.decide):
            raise AuthorityViolation(f"PROPOSE and DECIDE overlap: {cell.decision}")


def who_decides(decision: str) -> AuthorityCell:
    for cell in AUTHORITY_TABLE:
        if cell.decision == decision:
            return cell
    raise KeyError(f"unknown decision: {decision!r} (authority table is fixed by spec §4)")


@dataclass(frozen=True)
class VetoRecord:
    """D0-02 binding rule 2: VETO is final; it terminates the FSM-2 path into
    REJECTED. Only a *new* change object (new DRAFT) can restart."""

    change_id: str
    actor: str              # RBAC identity of the vetoing human, or "A4_AUDITOR"
    reason: str
    evidence_ids: tuple[str, ...]


def veto(change_id: str, actor: str, reason: str, evidence_ids) -> VetoRecord:
    """Construct a final veto record. Identity and reason are mandatory —
    an anonymous or unreasoned veto is an audit violation (D0-02 rule 5)."""
    if not change_id or not actor or not reason:
        raise ValueError("VETO requires change_id, actor identity and reason")
    return VetoRecord(change_id=change_id, actor=actor, reason=reason,
                      evidence_ids=tuple(evidence_ids))


assert_authority_invariants()

__all__ = ["AUTHORITY_TABLE", "HUMAN_ONLY", "AuthorityCell", "AuthorityViolation",
           "VetoRecord", "veto", "who_decides", "assert_authority_invariants"]
