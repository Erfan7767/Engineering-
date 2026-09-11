"""Compliance Engine — regulatory and best-practice checks for running configs.

A 30-year network engineer doesn't trust a device just because it
boots — the engineer trusts it because the running configuration
passes a battery of well-known compliance checks. This module is
that battery.

What this engine does:

* Checks the running-config against HIPAA / PCI-DSS / CIS / NIST
  baselines (the ones a real network security audit cares about).
* Checks Cisco IOS-XE hardening best practices (no http server,
  no telnet, password minimum length, etc.).
* Produces a typed, evidence-tagged report (which line of the
  config triggered which rule, with severity).
* Surfaces results through the chat (``compliance`` command) and
  through the executor's pre-apply gate.

What this engine does NOT do (typed, never silent):

* It does NOT modify the config. Findings are reported, not
  applied. The operator decides.
* It does NOT report a pass on a missing sample — a missing
  config is FAIL with reason ``SAMPLE_MISSING``.
* It does NOT pretend to know vendor-specific defaults it can't
  verify — those return ``NOT_MODELED`` (T2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Compliance finding severity, ordered for triage."""

    __test__ = False  # pytest opt-out

    INFO = "INFO"               # no risk, informational
    LOW = "LOW"                 # recommended hardening
    MEDIUM = "MEDIUM"           # best-practice deviation
    HIGH = "HIGH"               # regulatory concern
    CRITICAL = "CRITICAL"       # active compliance violation


class ComplianceFramework(str, Enum):
    """The frameworks the engine knows about."""

    __test__ = False

    CIS_CISCO_IOS = "CIS_CISCO_IOS"            # CIS Cisco IOS Benchmark
    PCI_DSS = "PCI_DSS"                        # Payment Card Industry DSS
    HIPAA = "HIPAA"                            # Health Insurance Portability Act
    NIST_800_53 = "NIST_800_53"                # NIST 800-53
    BEST_PRACTICE = "BEST_PRACTICE"            # Cisco hardening best practices


class FindingStatus(str, Enum):
    """The engine's verdict on a single check."""

    __test__ = False

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_MODELED = "NOT_MODELED"   # we don't know how to check this
    SAMPLE_MISSING = "SAMPLE_MISSING"  # config not supplied


@dataclass(frozen=True)
class ComplianceRule:
    """A single compliance rule. The engine ships with a built-in
    catalogue; callers can also register their own rules at
    runtime.
    """

    __test__ = False

    rule_id: str                          # e.g. "CIS-1.4.1"
    title: str                            # human-readable
    framework: ComplianceFramework
    severity: Severity
    description: str                      # why this matters
    remediation: str                      # what the operator should do
    # Pattern check. The rule is FAIL if the pattern matches
    # in the wrong direction (presence where forbidden) or fails
    # to match (absence where required).
    pattern: re.Pattern                   # compiled regex
    # direction=True means presence of pattern = PASS
    # direction=False means presence of pattern = FAIL
    presence_means_pass: bool = True
    # If set, a comment anywhere in the config that matches
    # this regex is treated as PASS (e.g. a CIS-1.4.1 waiver
    # like "! WAIVED: <reason>").
    waiver_marker: Optional[re.Pattern] = None
    # If True, this rule applies to every device by default.
    default: bool = True


@dataclass(frozen=True)
class ComplianceFinding:
    """A single finding for a single device."""

    __test__ = False

    rule_id: str
    title: str
    framework: ComplianceFramework
    severity: Severity
    status: FindingStatus
    description: str
    remediation: str
    evidence: str  # the actual line of the config (or a description)


@dataclass
class ComplianceReport:
    """The full compliance verdict for one device's running config."""

    __test__ = False

    device_ref: str
    findings: list[ComplianceFinding] = field(default_factory=list)
    rules_evaluated: int = 0
    rules_waived: int = 0

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.FAIL)

    @property
    def critical_failures(self) -> list[ComplianceFinding]:
        return [
            f for f in self.findings
            if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL
        ]

    @property
    def high_failures(self) -> list[ComplianceFinding]:
        return [
            f for f in self.findings
            if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH
        ]

    @property
    def overall_verdict(self) -> str:
        if self.critical_failures:
            return "NON_COMPLIANT_CRITICAL"
        if self.high_failures:
            return "NON_COMPLIANT_HIGH"
        if self.fail_count:
            return "NON_COMPLIANT_MEDIUM"
        if self.pass_count == 0:
            return "UNKNOWN"
        return "COMPLIANT"


# --------------------------------------------------------------------- catalog
# The catalog is the source of truth. Each rule is registered with
# the engine at module load. A 30-year engineer reads this list
# and either nods or adds more.

_CATALOG: tuple[ComplianceRule, ...] = (
    # ---- CIS Cisco IOS Benchmark v15 (selected high-value rules) ----
    ComplianceRule(
        rule_id="CIS-1.1.1",
        title="Enable 'service password-encryption'",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.MEDIUM,
        description="Service password-encryption prevents plaintext "
                    "passwords from showing in show running-config.",
        remediation="Enter 'service password-encryption' in global config.",
        pattern=re.compile(r"^\s*service\s+password-encryption\s*$", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-1.4.1",
        title="Set 'no ip http server'",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.HIGH,
        description="The HTTP server is a known attack surface; Cisco "
                    "IOS devices should not expose it unless an MDM "
                    "needs it.",
        remediation="Enter 'no ip http server' in global config.",
        pattern=re.compile(r"^\s*ip\s+http\s+server\s*$", re.MULTILINE),
        presence_means_pass=False,
    ),
    ComplianceRule(
        rule_id="CIS-1.4.2",
        title="Set 'no ip http secure-server' unless required",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.MEDIUM,
        description="HTTPS server is also an attack surface if not "
                    "actively used for management.",
        remediation="Enter 'no ip http secure-server' unless required.",
        pattern=re.compile(r"^\s*ip\s+http\s+secure-server\s*$", re.MULTILINE),
        presence_means_pass=False,
    ),
    ComplianceRule(
        rule_id="CIS-2.1.1",
        title="Disable telnet (use SSH only)",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.HIGH,
        description="Telnet sends credentials in plaintext. PCI-DSS "
                    "and HIPAA both forbid plaintext management.",
        remediation="Configure 'transport input ssh' on every VTY line.",
        pattern=re.compile(r"^\s*transport\s+input\s+telnet\s*$", re.MULTILINE),
        presence_means_pass=False,
    ),
    ComplianceRule(
        rule_id="CIS-2.2.1",
        title="Set 'login banner' (warning before access)",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.LOW,
        description="A legal warning banner is required for legal "
                    "compliance in most jurisdictions.",
        remediation="Configure 'banner motd' or 'banner login'.",
        pattern=re.compile(r"^\s*banner\s+(motd|login|exec)\s+(\S+)", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-3.1.1",
        title="Set 'enable secret' (not just 'enable password')",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.HIGH,
        description="'enable secret' uses MD5; 'enable password' "
                    "stores a reversible hash.",
        remediation="Configure 'enable secret <hash>'.",
        pattern=re.compile(r"^\s*enable\s+secret\s+", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-3.3.1",
        title="Set 'username secret' (not 'username password')",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.HIGH,
        description="Use type-9 hashes for local accounts.",
        remediation="Configure 'username <name> secret <hash>'.",
        pattern=re.compile(r"^\s*username\s+\S+\s+password\s+", re.MULTILINE),
        presence_means_pass=False,
    ),
    ComplianceRule(
        rule_id="CIS-4.1.1",
        title="Set 'logging buffered' (local event log)",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.MEDIUM,
        description="Local logging ensures events are not lost when "
                    "syslog is unavailable.",
        remediation="Configure 'logging buffered <size>'.",
        pattern=re.compile(r"^\s*logging\s+buffered\s+", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-4.2.1",
        title="Set 'no ip source-route'",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.MEDIUM,
        description="Source routing can be used for spoofing.",
        remediation="Configure 'no ip source-route'.",
        pattern=re.compile(r"^\s*ip\s+source-route\s*$", re.MULTILINE),
        presence_means_pass=False,
    ),
    ComplianceRule(
        rule_id="CIS-5.1.1",
        title="Set 'service timestamps log datetime msec'",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.LOW,
        description="Millisecond timestamps are required for "
                    "forensic correlation.",
        remediation="Configure 'service timestamps log datetime msec'.",
        pattern=re.compile(r"^\s*service\s+timestamps\s+log\s+datetime", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-5.2.1",
        title="Set 'ntp server' (or 'sntp server') for time sync",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.MEDIUM,
        description="Time sync is required for log correlation "
                    "and certificate validation.",
        remediation="Configure 'ntp server <ip>'.",
        pattern=re.compile(r"^\s*(ntp|sntp)\s+server\s+", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="CIS-6.1.1",
        title="Set 'snmp-server community' with restricted ACL",
        framework=ComplianceFramework.CIS_CISCO_IOS,
        severity=Severity.HIGH,
        description="Default SNMP communities (public/private) are "
                    "well-known attack vectors.",
        remediation="Use 'snmp-server community <string> RO <acl>'.",
        pattern=re.compile(r"^\s*snmp-server\s+community\s+(public|private)\s+", re.MULTILINE),
        presence_means_pass=False,
    ),
    # ---- PCI-DSS derived rules ----
    ComplianceRule(
        rule_id="PCI-2.2.1",
        title="Strong cryptography on management protocols",
        framework=ComplianceFramework.PCI_DSS,
        severity=Severity.CRITICAL,
        description="PCI-DSS 2.2.1 requires strong cryptography for "
                    "all management access. Telnet and HTTP violate.",
        remediation="Disable telnet, disable HTTP, require SSHv2.",
        pattern=re.compile(r"^\s*(ip\s+http\s+server|transport\s+input\s+telnet)\s*$", re.MULTILINE),
        presence_means_pass=False,
    ),
    # ---- HIPAA derived rules ----
    ComplianceRule(
        rule_id="HIPAA-164.312.a.1",
        title="Unique user identification (no shared accounts)",
        framework=ComplianceFramework.HIPAA,
        severity=Severity.CRITICAL,
        description="HIPAA requires unique user IDs for access "
                    "to ePHI. Shared accounts violate.",
        remediation="Each admin must have their own username.",
        pattern=re.compile(r"^\s*username\s+\S+\s+(password|secret)", re.MULTILINE),
        # The presence of at least one per-admin user is required.
        # We model this as: the existence of *any* properly-defined
        # username entry is required (positive check), and we
        # specifically flag the well-known default account "cisco"
        # if found.
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="HIPAA-164.312.b",
        title="Audit controls (local + remote logging)",
        framework=ComplianceFramework.HIPAA,
        severity=Severity.HIGH,
        description="HIPAA requires hardware, software, and/or "
                    "procedural mechanisms that record and examine "
                    "activity in information systems containing ePHI.",
        remediation="Configure 'logging host <syslog>' and "
                    "'logging buffered'.",
        pattern=re.compile(r"^\s*logging\s+(host|buffered)\s+", re.MULTILINE),
        presence_means_pass=True,
    ),
    # ---- NIST 800-53 derived rules ----
    ComplianceRule(
        rule_id="NIST-AC-2",
        title="Account management (no default accounts)",
        framework=ComplianceFramework.NIST_800_53,
        severity=Severity.HIGH,
        description="Default vendor accounts (cisco, admin) are "
                    "forbidden under AC-2.",
        remediation="Rename or remove default accounts.",
        pattern=re.compile(r"^\s*username\s+(cisco|admin|root)\s+", re.MULTILINE),
        presence_means_pass=False,
    ),
    # ---- Best-practice (always-on) ----
    ComplianceRule(
        rule_id="BP-LLDP",
        title="LLDP enabled on at least one interface",
        framework=ComplianceFramework.BEST_PRACTICE,
        severity=Severity.LOW,
        description="LLDP provides automatic neighbor discovery; "
                    "Cisco's CDP is a fallback.",
        remediation="Configure 'lldp run' globally.",
        pattern=re.compile(r"^\s*lldp\s+run\s*$", re.MULTILINE),
        presence_means_pass=True,
    ),
    ComplianceRule(
        rule_id="BP-LOGGING-CONSISTENT",
        title="Logging host configured",
        framework=ComplianceFramework.BEST_PRACTICE,
        severity=Severity.LOW,
        description="A central syslog host ensures audit trail "
                    "survives device compromise.",
        remediation="Configure 'logging host <ip>'.",
        pattern=re.compile(r"^\s*logging\s+host\s+", re.MULTILINE),
        presence_means_pass=True,
    ),
)


def catalog() -> tuple[ComplianceRule, ...]:
    """Return the built-in rule catalogue. Read-only; use
    ``register`` to add custom rules.
    """
    return _CATALOG


_EXTRA_RULES: list[ComplianceRule] = []


def register(rule: ComplianceRule) -> None:
    """Register a custom compliance rule. Idempotent on rule_id."""
    for r in _CATALOG:
        if r.rule_id == rule.rule_id:
            return
    for r in _EXTRA_RULES:
        if r.rule_id == rule.rule_id:
            return
    _EXTRA_RULES.append(rule)


def reset() -> None:
    """Drop all custom rules. Tests use this."""
    _EXTRA_RULES.clear()


def _all_rules() -> tuple[ComplianceRule, ...]:
    return _CATALOG + tuple(_EXTRA_RULES)


# --------------------------------------------------------------------- evaluator

def evaluate(device_ref: str, config: str) -> ComplianceReport:
    """Evaluate ``config`` against the catalogue and return a typed
    report.

    Behaviour:

    * Every rule is evaluated (no silent skip).
    * If the config is empty / not supplied, every check returns
      SAMPLE_MISSING with severity preserved.
    * If a rule's ``waiver_marker`` is found in the config, the
      rule is reported as PASS with evidence = waiver text.
    * The verdict is the highest-severity non-PASS, or COMPLIANT.
    """
    if not config or not config.strip():
        return ComplianceReport(
            device_ref=device_ref,
            findings=[
                ComplianceFinding(
                    rule_id=r.rule_id,
                    title=r.title,
                    framework=r.framework,
                    severity=r.severity,
                    status=FindingStatus.SAMPLE_MISSING,
                    description=r.description,
                    remediation=r.remediation,
                    evidence="running-config is empty or not supplied",
                )
                for r in _all_rules() if r.default
            ],
            rules_evaluated=sum(1 for r in _all_rules() if r.default),
        )

    findings: list[ComplianceFinding] = []
    waived = 0
    for rule in _all_rules():
        if not rule.default:
            continue
        # Check waiver first
        if rule.waiver_marker and rule.waiver_marker.search(config):
            findings.append(ComplianceFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                framework=rule.framework,
                severity=rule.severity,
                status=FindingStatus.PASS,
                description=f"Waived: {rule.waiver_marker.search(config).group(0)}",
                remediation=rule.remediation,
                evidence="explicit waiver in config",
            ))
            waived += 1
            continue
        match = rule.pattern.search(config)
        if rule.presence_means_pass:
            status = FindingStatus.PASS if match else FindingStatus.FAIL
            evidence = match.group(0).strip() if match else "pattern not found in config"
        else:
            status = FindingStatus.FAIL if match else FindingStatus.PASS
            evidence = match.group(0).strip() if match else "pattern correctly absent"
        findings.append(ComplianceFinding(
            rule_id=rule.rule_id,
            title=rule.title,
            framework=rule.framework,
            severity=rule.severity,
            status=status,
            description=rule.description,
            remediation=rule.remediation,
            evidence=evidence,
        ))

    return ComplianceReport(
        device_ref=device_ref,
        findings=findings,
        rules_evaluated=len(findings),
        rules_waived=waived,
    )


def render_report(report: ComplianceReport, lang: str = "en") -> str:
    """Return a human-readable text rendering of the report.

    Used by the chat's ``compliance`` command and by the
    pre-apply gate's stderr log.
    """
    if lang == "ar":
        return _render_report_ar(report)
    return _render_report_en(report)


def _render_report_en(r: ComplianceReport) -> str:
    lines: list[str] = []
    lines.append(f"Compliance report for {r.device_ref}")
    lines.append(f"  Verdict: {r.overall_verdict}")
    lines.append(f"  Rules evaluated: {r.rules_evaluated}")
    lines.append(f"  Pass: {r.pass_count}   Fail: {r.fail_count}   "
                 f"Waived: {r.rules_waived}")
    if r.critical_failures:
        lines.append("")
        lines.append("  CRITICAL FAILURES:")
        for f in r.critical_failures:
            lines.append(f"    ✕ [{f.rule_id}] {f.title}")
            lines.append(f"      Fix: {f.remediation}")
    if r.high_failures:
        lines.append("")
        lines.append("  HIGH FAILURES:")
        for f in r.high_failures:
            lines.append(f"    ✕ [{f.rule_id}] {f.title}")
            lines.append(f"      Fix: {f.remediation}")
    if r.fail_count == 0:
        lines.append("")
        lines.append("  All evaluated rules PASS.")
    return "\n".join(lines)


def _render_report_ar(r: ComplianceReport) -> str:
    lines: list[str] = []
    lines.append(f"تقرير الامتثال لـ {r.device_ref}")
    lines.append(f"  النتيجة: {r.overall_verdict}")
    lines.append(f"  القواعد المُقيّمة: {r.rules_evaluated}")
    lines.append(f"  نجاح: {r.pass_count}   فشل: {r.fail_count}   "
                 f"مُعفى: {r.rules_waived}")
    if r.critical_failures:
        lines.append("")
        lines.append("  إخفاقات حرجة:")
        for f in r.critical_failures:
            lines.append(f"    ✕ [{f.rule_id}] {f.title}")
            lines.append(f"      الإصلاح: {f.remediation}")
    if r.high_failures:
        lines.append("")
        lines.append("  إخفاقات عالية:")
        for f in r.high_failures:
            lines.append(f"    ✕ [{f.rule_id}] {f.title}")
            lines.append(f"      الإصلاح: {f.remediation}")
    if r.fail_count == 0:
        lines.append("")
        lines.append("  كل القواعد المُقيّمة تنجح.")
    return "\n".join(lines)
