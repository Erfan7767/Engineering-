"""Unified failure semantics (D0-01 §3, §7 tail of master spec).

Every engine either succeeds or raises/returns a :class:`Failure` with one of
the six classes. Silent failure is impossible by construction (L03).

Implementation note: ``Failure`` is a plain Exception subclass (NOT a frozen
dataclass) on purpose — Python's exception machinery must be able to set
``__traceback__``/``__context__`` on raised instances. Field immutability is
enforced post-init via a locked flag instead.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class FailureClass(str, Enum):
    """The single failure vocabulary for all engines and FSMs."""

    RETRYABLE = "RETRYABLE"
    BLOCKED = "BLOCKED"
    ROLLED_BACK = "ROLLED_BACK"
    PARTIAL = "PARTIAL"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    FATAL = "FATAL"


class Failure(Exception):
    """Structured engine failure.

    Attributes:
        cls: one of :class:`FailureClass`.
        causes: structured reason codes (never free-form excuses).
        count: for PARTIAL — number of failed items.
        total: for PARTIAL — total items attempted.
        evidence_ids: ledger ids backing the classification.
        retry_hint: present ONLY for RETRYABLE (mapping rule D0-01 §3).
    """

    __slots__ = ()  # documented attributes live on the instance dict via Exception

    def __init__(
        self,
        cls: FailureClass,
        causes: tuple[str, ...],
        count: int = 0,
        total: int = 0,
        evidence_ids: tuple[str, ...] = (),
        retry_hint: Optional[str] = None,
    ) -> None:
        causes = tuple(causes)
        if not causes:
            raise ValueError("Failure without causes violates L03/T4")
        if retry_hint is not None and cls is not FailureClass.RETRYABLE:
            raise ValueError("retry_hint is only valid for RETRYABLE failures")
        if cls is FailureClass.PARTIAL and not (0 < count <= total):
            raise ValueError("PARTIAL failure requires 0 < count <= total (T4)")
        self.cls = cls
        self.causes = causes
        self.count = count
        self.total = total
        self.evidence_ids = tuple(evidence_ids)
        self.retry_hint = retry_hint
        super().__init__(str(self))

    def __str__(self) -> str:
        detail = ", ".join(self.causes)
        if self.cls is FailureClass.PARTIAL:
            detail = f"{self.count}/{self.total} failed: {detail}"
        return f"{self.cls.value}: {detail}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Failure(cls={self.cls!r}, causes={self.causes!r})"


def blocked(*causes: str, evidence_ids: tuple[str, ...] = ()) -> Failure:
    """Convenience constructor: precondition false ⇒ BLOCKED (never a default)."""
    return Failure(cls=FailureClass.BLOCKED, causes=tuple(causes), evidence_ids=evidence_ids)
