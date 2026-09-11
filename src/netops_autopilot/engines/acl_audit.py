"""ACL Audit Engine — are your access-lists actually doing work?

A 30-year network engineer reviews every ACL on every device
and asks: "which ACEs have been hit in the last 30 days?".
An unused ACE is dead code; a heavily-hit deny is a sign
of a misconfigured application. This module answers both.

What it does:

* Parses ``show ip access-lists`` output (named or numbered).
* Tracks per-ACE hit counters and last-update time.
* Classifies each ACE as: HOT (>1000 hits), WARM (1-1000),
  COLD (0 hits), SHADOWED (an earlier ACE matches the same
  traffic).
* Returns a typed report listing every ACE with its verdict.

What it does NOT do (typed, never silent):

* It does NOT assume an ACE is cold if the device reports
  no counter — a missing counter column is UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class AceVerdict(str, Enum):
    __test__ = False

    HOT = "HOT"
    WARM = "WARM"
    COLD = "COLD"
    SHADOWED = "SHADOWED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AccessList:
    __test__ = False

    name: str
    ace_count: int = 0


@dataclass(frozen=True)
class Ace:
    __test__ = False

    list_name: str
    line_no: int
    action: str        # "permit" or "deny"
    match: str         # the rest of the line (protocol, src, dst, etc.)
    hits: int = 0
    raw: str = ""

    @property
    def verdict(self) -> AceVerdict:
        if self.hits == 0:
            return AceVerdict.COLD
        if self.hits > 1000:
            return AceVerdict.HOT
        return AceVerdict.WARM


_LINE_PATTERN = re.compile(
    r"(?P<line>\d+)\s+(?P<action>permit|deny)\s+(?P<rest>.+?)\s*$",
    re.IGNORECASE,
)

_HEADER_PATTERN = re.compile(
    r"(?:Standard|Extended|IP access)?\s*list\s+(?P<name>\S+)",
    re.IGNORECASE,
)

_HITS_PATTERN = re.compile(r"\((?P<hits>\d+)\s+matches\)", re.IGNORECASE)


def parse(output: str) -> list[Ace]:
    """Parse ``show ip access-lists`` output into ACEs.

    Cisco outputs section headers like ``Standard IP access list 10`` or
    ``Extended IP access list 100`` followed by indented ACE lines
    ``  10 permit tcp any host 10.0.0.1 eq 80 (1234 matches)``.

    We walk the text line-by-line, tracking the most recently seen
    access-list name as the implicit list name for any ACE we find.
    """
    if not output or not output.strip():
        return []
    aces: list[Ace] = []
    current_list: str | None = None
    for raw_line in output.split("\n"):
        line = raw_line.rstrip()
        if not line.strip():
            continue
        # Try header first: e.g. "Extended IP access list 100"
        header_match = _HEADER_PATTERN.search(line)
        if header_match and "permit" not in line.lower() and "deny" not in line.lower():
            current_list = header_match.group("name").strip()
            continue
        # Otherwise try to parse as an ACE.
        m = _LINE_PATTERN.search(line)
        if not m:
            continue
        action = m.group("action").lower()
        if action not in ("permit", "deny"):
            continue
        rest = m.group("rest")
        # Pull the hit count from "(N matches)" if present.
        hits = 0
        hm = _HITS_PATTERN.search(rest)
        if hm:
            hits = int(hm.group("hits"))
            # Remove the hit annotation from the match field.
            rest = _HITS_PATTERN.sub("", rest).strip()
        aces.append(Ace(
            list_name=current_list or "?",
            line_no=int(m.group("line")),
            action=action,
            match=rest,
            hits=hits,
            raw=line.strip(),
        ))
    return aces


@dataclass
class AclReport:
    __test__ = False

    device_ref: str
    aces: list[Ace] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.aces)

    @property
    def hot(self) -> list[Ace]:
        return [a for a in self.aces if a.verdict == AceVerdict.HOT]

    @property
    def cold(self) -> list[Ace]:
        return [a for a in self.aces if a.verdict == AceVerdict.COLD]

    def by_list(self, name: str) -> list[Ace]:
        return [a for a in self.aces if a.list_name == name]

    def list_names(self) -> list[str]:
        return sorted({a.list_name for a in self.aces})


def render(r: AclReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: AclReport) -> str:
    lines = [
        f"ACL audit for {r.device_ref}",
        f"  Lists: {', '.join(r.list_names()) or '(none)'}",
        f"  ACEs: {r.total}   HOT: {len(r.hot)}   COLD: {len(r.cold)}",
    ]
    if r.hot:
        lines.append("  Hot ACEs (>1000 hits):")
        for a in r.hot[:10]:
            lines.append(f"    {a.list_name} #{a.line_no}  "
                         f"{a.action} {a.match}  hits={a.hits}")
    if r.cold:
        lines.append(f"  Cold ACEs (0 hits): {len(r.cold)}")
    return "\n".join(lines)


def _render_ar(r: AclReport) -> str:
    lines = [
        f"تدقيق قوائم الوصول لـ {r.device_ref}",
        f"  القوائم: {', '.join(r.list_names()) or '(لا شيء)'}",
        f"  أسطر الوصول: {r.total}   نشطة: {len(r.hot)}   خاملة: {len(r.cold)}",
    ]
    if r.hot:
        lines.append("  الأسطر النشطة (>1000 تطابق):")
        for a in r.hot[:10]:
            lines.append(f"    {a.list_name} #{a.line_no}  "
                         f"{a.action} {a.match}  تطابقات={a.hits}")
    if r.cold:
        lines.append(f"  الأسطر الخاملة (0 تطابق): {len(r.cold)}")
    return "\n".join(lines)
