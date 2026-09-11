"""Command Allowlist enforcement (specs/data/allowlists/*, D0).

Rules (allowlists README):
1. Only registered templates execute; everything else ⇒ BLOCKED (L10/T3).
2. The Collector is READ_ONLY-only in this release line; higher classes are
   reserved for E15 (D3) with their gates.
3. ``classify`` returns the class name or None (unknown ⇒ never allowed).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

#: Execution order: first matching class wins; FORBIDDEN is checked first so
#: a forbidden template can never hide inside a broader class by accident.
CLASS_PRIORITY = ("FORBIDDEN", "DESTRUCTIVE", "CONFIG_HIGH_RISK", "CONFIG_REVERSIBLE", "READ_ONLY")


@dataclass(frozen=True)
class AllowlistEntry:
    template: str
    cls: str
    purpose: str = ""
    notes: str = ""
    rollback: str = ""


class CommandAllowlist:
    """In-memory allowlist compiled from the JSON data files."""

    def __init__(self, entries: tuple[AllowlistEntry, ...] = ()) -> None:
        self._entries = tuple(entries)
        self._by_template: dict[str, AllowlistEntry] = {}
        for entry in self._entries:
            # Duplicate template across classes is a data defect, not a runtime guess.
            if entry.template in self._by_template and self._by_template[entry.template].cls != entry.cls:
                raise ValueError(f"template registered in two classes: {entry.template!r}")
            self._by_template[entry.template] = entry

    @classmethod
    def load_dir(cls, directory: str | Path) -> "CommandAllowlist":
        """Load every ``*.json`` allowlist file in a directory."""
        entries: list[AllowlistEntry] = []
        for path in sorted(Path(directory).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for cls_name, body in data.get("classes", {}).items():
                for raw in body.get("entries", []):
                    entries.append(
                        AllowlistEntry(
                            template=raw["template"],
                            cls=cls_name,
                            purpose=raw.get("purpose", ""),
                            notes=raw.get("notes", "") if cls_name != "FORBIDDEN" else raw.get("reason", ""),
                            rollback=raw.get("rollback", ""),
                        )
                    )
        return cls(tuple(entries))

    def classify(self, command: str) -> str | None:
        entry = self._by_template.get(command.strip())
        return entry.cls if entry else None

    def entry(self, command: str) -> AllowlistEntry | None:
        return self._by_template.get(command.strip())

    def is_readable(self, command: str) -> bool:
        """True iff the command is an explicitly allowlisted READ_ONLY entry."""
        return self.classify(command) == "READ_ONLY"

    def size(self) -> int:
        return len(self._entries)
