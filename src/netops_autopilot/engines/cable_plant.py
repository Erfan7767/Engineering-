"""Cable Plant Management — patch panel + fiber strand mapper.

A 30-year engineer maintains a cable plant: which patch
panel port goes to which wall jack, which fiber strand
goes to which floor. This module is the typed
implementation: take a CSV-like input of patch records,
surface typed :class:`PatchRecord` records and a typed
:class:`CablePlantReport`.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PatchRecord:
    __test__ = False

    panel: str
    port: str
    far_end: str
    cable_type: str = "cat6"
    length_meters: float = 0.0
    notes: str = ""


@dataclass
class CablePlantReport:
    __test__ = False

    site: str
    records: list[PatchRecord] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def fiber_count(self) -> int:
        return sum(
            1 for r in self.records
            if "fiber" in r.cable_type.lower()
            or "sm" in r.cable_type.lower()
            or "mm" in r.cable_type.lower()
        )

    @property
    def total_length_meters(self) -> float:
        return sum(r.length_meters for r in self.records)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"Cable plant: {self.record_count} سجل، "
                f"{self.fiber_count} ليف"
            )
        return (
            f"Cable plant: {self.record_count} record(s), "
            f"{self.fiber_count} fiber"
        )


_RECORD = re.compile(
    r"^(?P<panel>[A-Z]\d+):(?P<port>\d+)\s+->\s+"
    r"(?P<far>\S+)\s+(?P<type>\S+)"
    r"(?:\s+(?P<length>\d+)m)?",
    re.MULTILINE,
)


def parse_cable_plant(
    site: str,
    text: str,
) -> CablePlantReport:
    """Parse a free-form cable plant description."""
    rep = CablePlantReport(site=site)
    if not text or not text.strip():
        return rep
    for line in text.splitlines():
        m = _RECORD.match(line.strip())
        if not m:
            continue
        length_str = m.group("length")
        try:
            length = float(length_str) if length_str else 0.0
        except ValueError:
            length = 0.0
        rep.records.append(PatchRecord(
            panel=m.group("panel"),
            port=m.group("port"),
            far_end=m.group("far"),
            cable_type=m.group("type"),
            length_meters=length,
        ))
    return rep
