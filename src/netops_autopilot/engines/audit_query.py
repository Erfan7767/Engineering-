"""Audit Query Engine — typed queries against the signed ledger.

A 30-year engineer can answer "who changed VLAN 10 last
week?" in seconds by reading the audit trail. This module is
the typed implementation: take a :class:`LedgerStore` and a
:class:`AuditQuery`, return a :class:`AuditQueryResult` with
the matching events.

Design contract:

* **Deterministic** — same query + same ledger = same result.
* **Typed filters** — every filter is a typed
  :class:`AuditFilter`, not a raw SQL string.
* **Bounded** — the result has a hard ``limit`` and reports
  when truncated.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class AuditEventKind(str, Enum):
    __test__ = False

    CONFIG_CHANGE = "CONFIG_CHANGE"
    DISCOVERY = "DISCOVERY"
    APPLY = "APPLY"
    ROLLBACK = "ROLLBACK"
    SNAPSHOT = "SNAPSHOT"
    COMPLIANCE = "COMPLIANCE"
    CHAT = "CHAT"
    OBSERVATION = "OBSERVATION"
    ANY = "ANY"


@dataclass(frozen=True)
class AuditFilter:
    __test__ = False

    kind: AuditEventKind = AuditEventKind.ANY
    actor: str = ""
    target_device: str = ""
    text_contains: str = ""
    since_unix: float = 0.0
    until_unix: float = 0.0


@dataclass(frozen=True)
class AuditQuery:
    __test__ = False

    filters: tuple[AuditFilter, ...] = ()
    limit: int = 100
    order_desc: bool = True


@dataclass(frozen=True)
class AuditHit:
    __test__ = False

    event_id: str
    kind: str
    actor: str
    target: str
    summary: str
    timestamp_unix: float

    def render(self, lang: str = "en") -> str:
        ts = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.gmtime(self.timestamp_unix)
        )
        if lang == "ar":
            return (
                f"{ts}  {self.kind}  "
                f"{self.actor} → {self.target}  "
                f"{self.summary}"
            )
        return (
            f"{ts}  {self.kind}  "
            f"{self.actor} -> {self.target}  "
            f"{self.summary}"
        )


@dataclass
class AuditQueryResult:
    __test__ = False

    hits: list[AuditHit] = field(default_factory=list)
    truncated: bool = False
    total_matched: int = 0

    def render(self, lang: str = "en") -> str:
        head = (
            f"Audit query — {len(self.hits)} hit(s)"
            f"{' (truncated)' if self.truncated else ''}"
            if lang == "en"
            else f"استعلام التدقيق — {len(self.hits)} نتيجة"
            f"{' (مبتور)' if self.truncated else ''}"
        )
        if not self.hits:
            return head
        return head + "\n" + "\n".join(
            h.render(lang=lang) for h in self.hits
        )


def _coerce_events(store: Any) -> Iterable[Any]:
    """Pull the iterable of events from the store. The store
    may expose ``events()`` (LedgerStore in this repo) or
    ``events`` (a list). Both shapes are accepted.
    """
    if hasattr(store, "events") and callable(store.events):
        return store.events()
    if hasattr(store, "events"):
        return store.events
    return []


def _kind_of(ev: Any) -> str:
    """Map an event to a kind string. Tolerates multiple
    shapes (``event_type``, ``kind``, ``type_``)."""
    for attr in ("event_type", "kind", "type_", "type"):
        if hasattr(ev, attr):
            return str(getattr(ev, attr))
    return "OBSERVATION"


def _actor_of(ev: Any) -> str:
    if hasattr(ev, "actor"):
        a = getattr(ev, "actor")
        return str(getattr(a, "id", a))
    return ""


def _target_of(ev: Any) -> str:
    for attr in ("target", "device_ref", "subject"):
        if hasattr(ev, attr):
            return str(getattr(ev, attr) or "")
    return ""


def _summary_of(ev: Any) -> str:
    for attr in ("summary", "description", "value", "field"):
        if hasattr(ev, attr):
            return str(getattr(ev, attr) or "")
    return ""


def _ts_of(ev: Any) -> float:
    for attr in ("timestamp_unix", "created_at_unix", "ts_unix"):
        if hasattr(ev, attr):
            try:
                return float(getattr(ev, attr))
            except (TypeError, ValueError):
                pass
    return 0.0


def query(
    store: Any,
    q: AuditQuery,
) -> AuditQueryResult:
    """Run an :class:`AuditQuery` against the ledger."""
    events = list(_coerce_events(store))
    # Apply filters (AND across fields, OR across filters — each
    # filter is its own row of AND-ed predicates).
    matches: list[Any] = []
    for ev in events:
        if not _matches(ev, q.filters):
            continue
        matches.append(ev)
    matches.sort(
        key=lambda e: _ts_of(e),
        reverse=q.order_desc,
    )
    total = len(matches)
    truncated = total > q.limit
    matches = matches[: q.limit]
    hits = [
        AuditHit(
            event_id=str(getattr(ev, "event_id", _kind_of(ev))),
            kind=_kind_of(ev),
            actor=_actor_of(ev),
            target=_target_of(ev),
            summary=_summary_of(ev),
            timestamp_unix=_ts_of(ev),
        )
        for ev in matches
    ]
    return AuditQueryResult(
        hits=hits,
        truncated=truncated,
        total_matched=total,
    )


def _matches(ev: Any, filters: tuple[AuditFilter, ...]) -> bool:
    if not filters:
        return True
    ev_kind = _kind_of(ev)
    ev_actor = _actor_of(ev)
    ev_target = _target_of(ev)
    ev_summary = _summary_of(ev)
    ev_ts = _ts_of(ev)
    for f in filters:
        if f.kind != AuditEventKind.ANY:
            if not ev_kind.lower().startswith(f.kind.value.lower()):
                continue
        if f.actor and f.actor not in ev_actor:
            continue
        if f.target_device and f.target_device not in ev_target:
            continue
        if f.text_contains and f.text_contains not in ev_summary:
            continue
        if f.since_unix and ev_ts and ev_ts < f.since_unix:
            continue
        if f.until_unix and ev_ts and ev_ts > f.until_unix:
            continue
        return True
    return False
