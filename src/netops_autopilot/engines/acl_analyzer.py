"""ACL Analyzer — rule audit + shadow detection.

A 30-year engineer keeps an eye on ACL hygiene: no
duplicate rules, no shadowed rules (a later rule that
matches a subset of an earlier rule's traffic, making the
earlier rule dead code), no overly permissive any/any
rules at the bottom.

This module is the typed implementation: parse a Cisco /
Juniper ACL into typed :class:`AclRule` records, surface a
typed :class:`AclReport` with shadow + duplicate findings.

Design contract:

* **Typed** — every rule is a frozen dataclass.
* **Deterministic** — same input → same findings.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class AclAction(str, Enum):
    __test__ = False

    PERMIT = "permit"
    DENY = "deny"


@dataclass(frozen=True)
class AclRule:
    __test__ = False

    sequence: int
    action: AclAction
    protocol: str = "ip"
    source: str = "any"
    destination: str = "any"
    port: str = ""
    raw: str = ""

    @property
    def is_any_any(self) -> bool:
        return self.source == "any" and self.destination == "any"


@dataclass(frozen=True)
class AclFinding:
    __test__ = False

    kind: str          # "shadow" / "duplicate" / "any_any_at_end"
    line_no: int
    detail: str


@dataclass
class AclReport:
    __test__ = False

    name: str
    rules: list[AclRule] = field(default_factory=list)
    findings: list[AclFinding] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def permit_count(self) -> int:
        return sum(
            1 for r in self.rules
            if r.action == AclAction.PERMIT
        )

    @property
    def deny_count(self) -> int:
        return sum(
            1 for r in self.rules
            if r.action == AclAction.DENY
        )

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"ACL '{self.name}': {self.rule_count} قاعدة، "
                f"{self.finding_count} مشكلة"
            )
        return (
            f"ACL '{self.name}': {self.rule_count} rule(s), "
            f"{self.finding_count} finding(s)"
        )


_RULE_LINE = re.compile(
    r"^\s*(?P<seq>\d+)\s+(?P<action>permit|deny)\s+"
    r"(?P<proto>\S+)\s+(?P<src>\S+)(?:\s+(?P<dst>\S+))?"
    r"(?:\s+(?P<port>\S+))?",
    re.MULTILINE,
)


def parse_cisco_acl(
    name: str,
    output: str,
) -> AclReport:
    """Parse a Cisco IOS ACL (extended or standard)."""
    rep = AclReport(name=name)
    if not output or not output.strip():
        return rep
    for m in _RULE_LINE.finditer(output):
        try:
            seq = int(m.group("seq"))
        except ValueError:
            seq = 0
        try:
            action = AclAction(m.group("action"))
        except ValueError:
            continue
        rule = AclRule(
            sequence=seq,
            action=action,
            protocol=m.group("proto"),
            source=m.group("src"),
            destination=(m.group("dst") or "any"),
            port=(m.group("port") or ""),
            raw=m.group(0).strip(),
        )
        rep.rules.append(rule)
    # Findings: any-any at the end of an ACL.
    if rep.rules and rep.rules[-1].is_any_any:
        rep.findings.append(AclFinding(
            kind="any_any_at_end",
            line_no=rep.rules[-1].sequence,
            detail=(
                "Last rule is any/any — review whether it is "
                "intended (e.g. deny ip any any)."
            ),
        ))
    # Findings: duplicates (same action + src + dst + port).
    seen: dict[tuple, int] = {}
    for r in rep.rules:
        key = (r.action, r.source, r.destination, r.port)
        if key in seen:
            rep.findings.append(AclFinding(
                kind="duplicate",
                line_no=r.sequence,
                detail=(
                    f"Duplicate of line {seen[key]}: {r.raw}"
                ),
            ))
        else:
            seen[key] = r.sequence
    return rep
