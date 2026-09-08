"""Shared evidence helpers for FSM guards.

Evidence item shape (dict) used in guard contexts:
    {"scope": <verification_scope>, "kind": <str>, "evidence_id": <ledger id>,
     "status": "OK" | ...}

Guards never infer missing facts (L01): absence of required evidence ⇒ deny.
"""

from __future__ import annotations

from typing import Any

from .runtime import GuardOutcome


def items(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    return list(ctx.get("evidence", []))


def has_evidence(ctx: dict[str, Any], scope: str, status: str = "OK", kind: str | None = None) -> list[str]:
    """Evidence ids matching scope (+ optional exact kind) with required status."""
    out = []
    for item in items(ctx):
        if item.get("scope") != scope:
            continue
        if item.get("status", "OK") != status:
            continue
        if kind is not None and item.get("kind") != kind:
            continue
        eid = str(item.get("evidence_id", ""))
        if eid:
            out.append(eid)
    return out


def has_kinds(ctx: dict[str, Any], scope: str, kinds: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Return (found_ids, missing_kinds) for a required kind set."""
    found: list[str] = []
    missing: list[str] = []
    for kind in kinds:
        ids = has_evidence(ctx, scope, kind=kind)
        if ids:
            found.extend(ids)
        else:
            missing.append(kind)
    return found, missing


def deny_missing(what: str) -> GuardOutcome:
    return GuardOutcome.deny(f"MISSING_EVIDENCE: {what}")


def ev(scope: str, kind: str, eid: str = "ev-1", status: str = "OK") -> dict[str, Any]:
    """Test/caller convenience constructor for one evidence item."""
    return {"scope": scope, "kind": kind, "evidence_id": eid, "status": status}


def ctx(*evs: dict[str, Any]) -> dict[str, Any]:
    return {"evidence": list(evs)}
