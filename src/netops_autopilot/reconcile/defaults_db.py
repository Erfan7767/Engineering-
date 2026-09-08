"""Platform Defaults DB (P0-19, §12 reconciliation prerequisite).

Honesty rules enforced by the loader:
* every default value carries a ``source`` ∈ {documented, lab_verified};
* unknown facts are the literal string ``"UNKNOWN"`` (T2) and may carry no
  source other than ``not_recorded``;
* a value without source is a data defect ⇒ load error, never a guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Optional

VALID_SOURCES = ("documented", "lab_verified", "not_recorded")


@dataclass(frozen=True)
class DefaultValue:
    value: object
    source: str

    @property
    def unknown(self) -> bool:
        return self.value == "UNKNOWN"


class PlatformDefaults:
    """Defaults per platform key ``"<vendor>/<os>"`` → predicate → DefaultValue."""

    def __init__(self, data: dict) -> None:
        self._platforms: dict[str, dict[str, DefaultValue]] = {}
        for platform_key, predicates in data.get("platforms", {}).items():
            bucket: dict[str, DefaultValue] = {}
            for predicate, entry in predicates.items():
                if not isinstance(entry, dict) or "value" not in entry:
                    raise ValueError(f"defaults entry missing 'value': {platform_key}/{predicate}")
                source = entry.get("source")
                if source not in VALID_SOURCES:
                    raise ValueError(f"defaults entry missing valid source: {platform_key}/{predicate}")
                if entry["value"] != "UNKNOWN" and source == "not_recorded":
                    raise ValueError(f"non-UNKNOWN value cannot have source=not_recorded: {platform_key}/{predicate}")
                if entry["value"] == "UNKNOWN" and source != "not_recorded":
                    raise ValueError(f"UNKNOWN value must have source=not_recorded: {platform_key}/{predicate}")
                bucket[predicate] = DefaultValue(value=entry["value"], source=source)
            self._platforms[platform_key] = bucket

    @classmethod
    def load_builtin(cls) -> "PlatformDefaults":
        raw = resources.files("netops_autopilot.reconcile").joinpath("data/platform_defaults.json").read_text(encoding="utf-8")
        return cls(json.loads(raw))

    def default_for(self, platform_key: str, predicate: str) -> Optional[DefaultValue]:
        return self._platforms.get(platform_key, {}).get(predicate)

    def platforms(self) -> list[str]:
        return sorted(self._platforms)
