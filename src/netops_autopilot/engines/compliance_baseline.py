"""Compliance Baseline — typed rule packs (PCI/HIPAA/CIS/SOX).

A 30-year engineer runs compliance scans: PCI requires
SSH not Telnet, HIPAA requires encryption at rest, CIS
requires ``service password-encryption`` and ``aaa new-model``.

This module is the typed implementation: take a config
text, run a :class:`ComplianceRulePack` against it, and
return a typed :class:`ComplianceReport` with
:class:`ComplianceFinding` records.

Design contract:

* **Typed** — :class:`ComplianceRulePack` carries the
  rules with regex + verdict.
* **Deterministic** — same config + same pack → same
  report.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class ComplianceSeverity(str, Enum):
    __test__ = False

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ComplianceRule:
    __test__ = False

    id: str
    title: str
    pattern: str
    expect_match: bool = True
    severity: ComplianceSeverity = ComplianceSeverity.MEDIUM
    title_ar: str = ""


@dataclass
class ComplianceFinding:
    __test__ = False

    rule_id: str
    severity: ComplianceSeverity
    passed: bool
    detail: str = ""

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            tag = (
                "نجح" if self.passed else "فشل"
            )
        else:
            tag = (
                "PASS" if self.passed else "FAIL"
            )
        return f"[{self.severity.value}] {self.rule_id}: {tag}"


@dataclass
class ComplianceRulePack:
    __test__ = False

    name: str
    rules: list[ComplianceRule] = field(default_factory=list)


@dataclass
class ComplianceReport:
    __test__ = False

    pack_name: str
    findings: list[ComplianceFinding] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.passed)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if not f.passed)

    @property
    def overall_verdict(self) -> str:
        if self.fail_count == 0:
            return "PASS"
        # Critical fail -> FAIL_CRITICAL.
        if any(
            (not f.passed)
            and f.severity == ComplianceSeverity.CRITICAL
            for f in self.findings
        ):
            return "FAIL_CRITICAL"
        return "FAIL"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"الامتثال '{self.pack_name}': "
                f"{self.pass_count} نجح، {self.fail_count} فشل، "
                f"{self.overall_verdict}"
            )
        return (
            f"Compliance '{self.pack_name}': "
            f"{self.pass_count} pass, {self.fail_count} fail, "
            f"{self.overall_verdict}"
        )


# Pre-built rule packs (CIS / PCI / HIPAA / SOX).
_CIS_RULES: list[ComplianceRule] = [
    ComplianceRule(
        id="CIS-001",
        title="Enable service password-encryption",
        title_ar="تفعيل تشفير كلمات المرور",
        pattern=r"^\s*service\s+password-encryption\s*$",
        expect_match=True,
        severity=ComplianceSeverity.MEDIUM,
    ),
    ComplianceRule(
        id="CIS-002",
        title="Enable aaa new-model",
        title_ar="تفعيل aaa new-model",
        pattern=r"^\s*aaa\s+new-model\s*$",
        expect_match=True,
        severity=ComplianceSeverity.HIGH,
    ),
    ComplianceRule(
        id="CIS-003",
        title="Disable telnet on VTY lines",
        title_ar="تعطيل telnet على VTY",
        pattern=r"transport\s+input\s+telnet",
        expect_match=False,
        severity=ComplianceSeverity.HIGH,
    ),
]

_PCI_RULES: list[ComplianceRule] = [
    ComplianceRule(
        id="PCI-001",
        title="SSH must be enabled (PCI 2.2.4)",
        title_ar="SSH يجب تفعيله",
        pattern=r"^\s*ip\s+ssh\s+version\s+2\s*$",
        expect_match=True,
        severity=ComplianceSeverity.CRITICAL,
    ),
    ComplianceRule(
        id="PCI-002",
        title="No telnet server (PCI 2.2.4)",
        title_ar="لا telnet server",
        pattern=r"transport\s+input\s+telnet",
        expect_match=False,
        severity=ComplianceSeverity.CRITICAL,
    ),
]

_HIPAA_RULES: list[ComplianceRule] = [
    ComplianceRule(
        id="HIPAA-001",
        title="Service password-encryption required",
        title_ar="تشفير كلمات المرور",
        pattern=r"^\s*service\s+password-encryption\s*$",
        expect_match=True,
        severity=ComplianceSeverity.HIGH,
    ),
    ComplianceRule(
        id="HIPAA-002",
        title="Login block-for must be set",
        title_ar="login block-for",
        pattern=r"login\s+block-for",
        expect_match=True,
        severity=ComplianceSeverity.HIGH,
    ),
]


def get_pack(name: str) -> ComplianceRulePack:
    """Return a pre-built rule pack by name."""
    packs = {
        "cis": ComplianceRulePack(
            name="CIS", rules=_CIS_RULES,
        ),
        "pci": ComplianceRulePack(
            name="PCI", rules=_PCI_RULES,
        ),
        "hipaa": ComplianceRulePack(
            name="HIPAA", rules=_HIPAA_RULES,
        ),
    }
    return packs.get(name.lower(), ComplianceRulePack(name=name))


def run_pack(
    pack: ComplianceRulePack,
    config_text: str,
) -> ComplianceReport:
    """Run ``pack`` against ``config_text``."""
    rep = ComplianceReport(pack_name=pack.name)
    for rule in pack.rules:
        m = re.search(rule.pattern, config_text, re.MULTILINE)
        passed = bool(m) == rule.expect_match
        rep.findings.append(ComplianceFinding(
            rule_id=rule.id,
            severity=rule.severity,
            passed=passed,
            detail=rule.title,
        ))
    return rep
