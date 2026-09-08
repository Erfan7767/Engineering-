"""Adapter registry — deterministic binding resolution (ADR-0001 §3).

Resolution key is the IDENTIFIED tuple (vendor, platform, os, version) from
Inventory evidence (FSM-1 1.3). Engines call :meth:`AdapterRegistry.resolve`
and treat ``None`` as NOT_SUPPORTED — no vendor-name conditionals exist
outside this module, and this module decides by registered match data only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Callable, Optional


@dataclass(frozen=True)
class AdapterMatch:
    """Registration key. ``os`` narrows within a vendor; ``model_patterns``
    (fnmatch) further narrow; empty patterns = any model."""

    vendor: str
    os: Optional[str] = None
    model_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Registration:
    match: AdapterMatch
    factory: Callable[[], object]
    order: int


class AdapterRegistry:
    """Ordered, deterministic adapter bindings."""

    def __init__(self) -> None:
        self._regs: list[_Registration] = []

    def register(self, match: AdapterMatch, factory: Callable[[], object]) -> None:
        self._regs.append(_Registration(match=match, factory=factory, order=len(self._regs)))

    def resolve(self, *, vendor: str, os: Optional[str] = None, model: Optional[str] = None) -> Optional[object]:
        """First registration matching (vendor, os, model) wins.

        Specificity order inside registration order: an os-narrowed match
        beats a vendor-wide match regardless of insertion position, so
        late-arriving generic registrations cannot shadow specific ones.
        """
        candidates: list[tuple[tuple[int, int, int], _Registration]] = []
        for reg in self._regs:
            m = reg.match
            if m.vendor != vendor:
                continue
            os_specificity = 0
            if m.os is not None:
                if os is None or m.os != os:
                    continue
                os_specificity = 1
            model_specificity = 0
            if m.model_patterns:
                if model is None:
                    continue
                if not any(fnmatch(model, pat) for pat in m.model_patterns):
                    continue
                model_specificity = 1
            candidates.append(((os_specificity, model_specificity, -reg.order), reg))
        if not candidates:
            return None
        # Highest specificity first; tie-break by earliest registration.
        candidates.sort(key=lambda pair: (-pair[0][0], -pair[0][1], -pair[0][2]))
        return candidates[0][1].factory()

    def known_vendors(self) -> list[str]:
        return sorted({reg.match.vendor for reg in self._regs})
