"""Vendor-family detection from console banner/probe text — data-driven.

Reads ``specs/data/defaults_db/banner_markers.json``: marker substring
hits ⇒ candidate families. Zero hits ⇒ ZERO candidates (UNKNOWN — the
operator is asked, the platform never picks arbitrarily, T2). Multiple
hits ⇒ all of them, sorted; the caller treats >1 as ambiguous and asks.
"""

from __future__ import annotations

import json
from functools import lru_cache

from ..specs_data import specs_data_dir


@lru_cache(maxsize=1)
def _markers() -> dict[str, list[str]]:
    path_text = specs_data_dir("defaults_db", "banner_markers.json")
    if not path_text:
        return {}
    doc = json.loads(open(path_text, encoding="utf-8").read())
    return {family: [m.lower() for m in markers]
            for family, markers in doc.get("markers", {}).items()}


def detect_family_candidates(text: bytes | str) -> tuple[str, ...]:
    """Sorted candidate vendor families for the probe text (may be empty)."""
    folded = (text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text).lower()
    hits = [family for family, markers in _markers().items()
            if any(marker in folded for marker in markers)]
    return tuple(sorted(hits))
