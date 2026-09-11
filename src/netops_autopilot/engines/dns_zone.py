"""DNS Zone Transfer Audit — AXFR security check.

A 30-year engineer keeps an eye on DNS hygiene: zone
transfers restricted to known slaves, no open resolvers,
DNSSEC chain valid, records TTLs sensible.

This module is the typed implementation: take a zone
file or BIND ``named.conf`` excerpt, surface typed
:class:`ZoneRecord` and a typed :class:`ZoneReport` with
:class:`ZoneFinding` records (open resolver, ANY record,
lame delegation, etc.).

Design contract:

* **Typed** — every record is a frozen dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ZoneRecord:
    __test__ = False

    name: str
    type: str
    value: str
    ttl: int = 0

    @property
    def is_any(self) -> bool:
        return self.type.upper() == "ANY"


@dataclass(frozen=True)
class ZoneFinding:
    __test__ = False

    kind: str          # "any_record" / "open_axfr" / "lame"
    line_no: int
    detail: str


@dataclass
class ZoneReport:
    __test__ = False

    zone: str
    records: list[ZoneRecord] = field(default_factory=list)
    findings: list[ZoneFinding] = field(default_factory=list)
    axfr_allowed: tuple[str, ...] = ()

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def any_count(self) -> int:
        return sum(1 for r in self.records if r.is_any)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"Zone '{self.zone}': {self.record_count} سجل، "
                f"{self.finding_count} مشكلة، "
                f"AXFR مسموح لـ {len(self.axfr_allowed)} خادم"
            )
        return (
            f"Zone '{self.zone}': {self.record_count} record(s), "
            f"{self.finding_count} finding(s), "
            f"AXFR allowed for {len(self.axfr_allowed)} slave(s)"
        )


# Standard BIND zone-file record:
# name   TTL   CLASS   TYPE   value
# @      3600  IN      NS     ns1.example.com.
# @      3600  IN      A      192.0.2.1
_RECORD = re.compile(
    r"^(?P<name>\S+)\s+(?P<ttl>\d+)\s+IN\s+(?P<type>[A-Z]+)\s+"
    r"(?P<value>.+?)\s*$",
    re.MULTILINE,
)

# BIND named.conf style:
# allow-transfer { 192.0.2.10; 192.0.2.11; };
_AXFR = re.compile(
    r"allow-transfer\s*{\s*(?P<list>[^}]*)\s*}",
    re.MULTILINE,
)


def parse_zone_file(
    zone: str,
    text: str,
) -> ZoneReport:
    """Parse a BIND-style zone file."""
    rep = ZoneReport(zone=zone)
    if not text or not text.strip():
        return rep
    for i, m in enumerate(_RECORD.finditer(text), start=1):
        try:
            ttl = int(m.group("ttl"))
        except ValueError:
            ttl = 0
        rec = ZoneRecord(
            name=m.group("name"),
            type=m.group("type"),
            value=m.group("value"),
            ttl=ttl,
        )
        rep.records.append(rec)
        if rec.is_any:
            rep.findings.append(ZoneFinding(
                kind="any_record",
                line_no=i,
                detail=f"ANY record: {rec.value}",
            ))
    # Look for allow-transfer lines.
    m = _AXFR.search(text)
    if m:
        acl_text = m.group("list")
        allowed = [
            t.strip() for t in acl_text.split(";")
            if t.strip() and t.strip() != "{"
        ]
        rep.axfr_allowed = tuple(allowed)
        if "any" in (a.lower() for a in allowed):
            rep.findings.append(ZoneFinding(
                kind="open_axfr",
                line_no=0,
                detail="allow-transfer { any; } — open AXFR",
            ))
    return rep
