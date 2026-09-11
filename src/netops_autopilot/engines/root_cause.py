"""Root-Cause Analyzer — the 30-year expert's "why did this break?".

When a network breaks, the first question is always: "why?". A
junior engineer looks at the symptom; a senior engineer looks
for the *cause*. This module turns diagnostic findings into a
typed root-cause analysis: a ranked list of possible causes with
their confidence and the evidence that supports or refutes
each.

Design contract:

* **No LLM guessing** — every cause in the analysis is
  template-defined. The analyzer does not invent new causes.
* **Confidence is typed** — every cause has a
  :class:`Confidence` (HIGH / MEDIUM / LOW) backed by
  concrete evidence.
* **Evidence-bound** — every confidence value references the
  diagnostic field that supports it.
* **Bilingual** — rendering is in English or Arabic.

The cause catalogue is a small set of well-known patterns a
30-year engineer would check first. The list is open: any
new cause is a new :class:`CausePattern` row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Confidence(str, Enum):
    __test__ = False

    HIGH = "HIGH"         # root cause is identified
    MEDIUM = "MEDIUM"     # likely cause
    LOW = "LOW"           # possible but not confirmed


@dataclass(frozen=True)
class CausePattern:
    __test__ = False

    id: str
    title: str
    title_ar: str
    description: str
    description_ar: str
    check: Callable[[dict[str, Any]], Confidence]
    remediation_hint: str = ""
    remediation_hint_ar: str = ""


@dataclass
class RootCause:
    __test__ = False

    pattern: CausePattern
    confidence: Confidence
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class RootCauseAnalysis:
    __test__ = False

    problem: str
    problem_ar: str
    causes: list[RootCause] = field(default_factory=list)
    symptoms: list[str] = field(default_factory=list)

    @property
    def primary(self) -> RootCause | None:
        if not self.causes:
            return None
        order = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
        return sorted(
            self.causes,
            key=lambda c: order.index(c.confidence),
        )[0]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return self._render_ar()
        return self._render_en()

    def _render_en(self) -> str:
        lines = [f"Root-cause analysis: {self.problem}"]
        if self.symptoms:
            lines.append("  Symptoms:")
            for s in self.symptoms:
                lines.append(f"    - {s}")
        if not self.causes:
            lines.append("  No causes matched the current evidence.")
            return "\n".join(lines)
        lines.append("  Possible causes (ranked):")
        for i, c in enumerate(self.causes, 1):
            lines.append(
                f"    {i}. [{c.confidence.value}] {c.pattern.title}"
            )
            lines.append(f"       {c.pattern.description}")
            if c.pattern.remediation_hint:
                lines.append(f"       Try: {c.pattern.remediation_hint}")
        return "\n".join(lines)

    def _render_ar(self) -> str:
        lines = [f"تحليل السبب الجذري: {self.problem_ar}"]
        if self.symptoms:
            lines.append("  الأعراض:")
            for s in self.symptoms:
                lines.append(f"    - {s}")
        if not self.causes:
            lines.append("  لا توجد أسباب تطابق الدليل الحالي.")
            return "\n".join(lines)
        lines.append("  الأسباب المحتملة (مرتبة):")
        for i, c in enumerate(self.causes, 1):
            lines.append(
                f"    {i}. [{c.confidence.value}] {c.pattern.title_ar}"
            )
            lines.append(f"       {c.pattern.description_ar}")
            if c.pattern.remediation_hint_ar:
                lines.append(f"       جرّب: {c.pattern.remediation_hint_ar}")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# Cause catalogue
# ---------------------------------------------------------------------


_CATALOGUE: tuple[CausePattern, ...] = (
    CausePattern(
        id="dup_ip",
        title="Duplicate IP address",
        title_ar="عنوان IP مكرر",
        description=(
            "Two devices are using the same IP. The most common "
            "cause is a static IP that conflicts with DHCP."
        ),
        description_ar=(
            "جهازان يستخدمان نفس العنوان. السبب الشائع هو IP "
            "ثابت يتعارض مع DHCP."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("duplicate_ip") else Confidence.LOW
        ),
        remediation_hint=(
            "Run 'show arp' on the L3 device and compare MACs. "
            "Or 'ping <ip> from <device> with both source IPs'."
        ),
        remediation_hint_ar=(
            "شغّل 'show arp' على الجهاز وقارن العناوين الفيزيائية."
        ),
    ),
    CausePattern(
        id="cable_fault",
        title="Cable fault",
        title_ar="عطل في الكابل",
        description=(
            "CRC errors and lost-carrier counters indicate a "
            "physical-layer problem: bad cable, dirty connector, "
            "or a port hardware fault."
        ),
        description_ar=(
            "أخطاء CRC وفقدان الموجة الحاملة تشير إلى مشكلة فيزيائية: "
            "كابل تالف أو موصل متسخ أو عطل في منفذ الجهاز."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("crc_errors", 0) > 100
            else Confidence.MEDIUM if e.get("crc_errors", 0) > 10
            else Confidence.LOW
        ),
        remediation_hint=(
            "Replace the cable. If the error persists after "
            "a known-good cable, replace the SFP/port."
        ),
        remediation_hint_ar=(
            "استبدل الكابل. إن استمر العطل، استبدل SFP/المنفذ."
        ),
    ),
    CausePattern(
        id="speed_duplex_mismatch",
        title="Speed/duplex mismatch",
        title_ar="عدم تطابق السرعة/الازدواج",
        description=(
            "One side is hard-set to 100/full while the other "
            "is auto-negotiating. Result: late collisions, "
            "input errors, and slow throughput."
        ),
        description_ar=(
            "جانب مضبوط يدوياً على 100/full والآخر يفاوض تلقائياً. "
            "النتيجة: تصادمات متأخرة وبطء في النقل."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("speed_duplex_mismatch")
            else Confidence.LOW
        ),
        remediation_hint="Set both sides to auto-negotiate, or both to the same hard-coded speed/duplex.",
        remediation_hint_ar="اضبط الجانبين على التفاوض التلقائي، أو على نفس السرعة/الازدواج يدوياً.",
    ),
    CausePattern(
        id="mtu_mismatch",
        title="MTU mismatch",
        title_ar="عدم تطابق MTU",
        description=(
            "One side has MTU 1500, the other has 9000 (jumbo). "
            "Symptoms: large pings fail, small pings succeed."
        ),
        description_ar=(
            "جانب MTU 1500 والآخر 9000 (jumbo). الأعراض: "
            "الـping الكبيرة تفشل والصغيرة تنجح."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("mtu_mismatch")
            else Confidence.LOW
        ),
        remediation_hint=(
            "Match the MTU end-to-end. Use 'show interface' to "
            "verify on both sides."
        ),
        remediation_hint_ar="طابق MTU على الطرفين. استخدم 'show interface' للتحقق.",
    ),
    CausePattern(
        id="vlan_mismatch",
        title="VLAN mismatch",
        title_ar="عدم تطابق VLAN",
        description=(
            "One trunk is carrying VLAN 10, the other is "
            "filtering it out. Symptom: hosts in the same VLAN "
            "can't reach each other across a switch."
        ),
        description_ar=(
            "ترانك يحمل VLAN 10 والآخر يفلترها. الأعراض: "
            "أجهزة في نفس VLAN لا تصل لبعضها."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("vlan_mismatch")
            else Confidence.MEDIUM if e.get("vlan_mismatch_partial")
            else Confidence.LOW
        ),
        remediation_hint=(
            "Check 'show interfaces trunk' on both sides and "
            "align the allowed VLAN list."
        ),
        remediation_hint_ar=(
            "افحص 'show interfaces trunk' على الجانبين وطابق قائمة VLAN المسموحة."
        ),
    ),
    CausePattern(
        id="stp_blocking",
        title="STP blocking the path",
        title_ar="STP يحجب المسار",
        description=(
            "Spanning-tree placed one of the uplinks in "
            "BLOCKING state. Check the root bridge and root port."
        ),
        description_ar=(
            "STP وضع أحد الروابط في حالة BLOCKING. افحص الـroot bridge والمنفذ الجذر."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("stp_blocked")
            else Confidence.LOW
        ),
        remediation_hint=(
            "Check 'show spanning-tree' on both switches. "
            "Verify the priority and the root port."
        ),
        remediation_hint_ar=(
            "افحص 'show spanning-tree' على المحولين. تحقق من الأولوية والمنفذ الجذر."
        ),
    ),
    CausePattern(
        id="ospf_area_mismatch",
        title="OSPF area mismatch",
        title_ar="عدم تطابق منطقة OSPF",
        description=(
            "Two OSPF neighbors on the same link but in "
            "different areas — the adjacency will not form."
        ),
        description_ar=(
            "جيران OSPF على نفس الرابط لكن في مناطق مختلفة — "
            "الجوار لن يتشكل."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("ospf_area_mismatch")
            else Confidence.LOW
        ),
        remediation_hint=(
            "Run 'show ip ospf interface' on both sides and "
            "align the area number."
        ),
        remediation_hint_ar=(
            "شغّل 'show ip ospf interface' على الجانبين وطابق رقم المنطقة."
        ),
    ),
    CausePattern(
        id="bgp_as_mismatch",
        title="BGP AS mismatch",
        title_ar="عدم تطابق BGP AS",
        description=(
            "Two BGP neighbors configured with different "
            "remote-as numbers — the session stays in Active."
        ),
        description_ar=(
            "جيران BGP مضبوطين بـ remote-as مختلف — "
            "الجلسة تبقى في Active."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("bgp_as_mismatch")
            else Confidence.LOW
        ),
        remediation_hint=(
            "Run 'show ip bgp summary' and verify the remote-as "
            "matches the peer's local-as."
        ),
        remediation_hint_ar=(
            "شغّل 'show ip bgp summary' وتحقق من تطابق remote-as مع local-as للطرف."
        ),
    ),
    CausePattern(
        id="acl_shadowing",
        title="ACL shadowing",
        title_ar="تظليل ACL",
        description=(
            "An earlier ACE in the same list makes a later "
            "ACE unreachable. The later ACE shows 0 hits."
        ),
        description_ar=(
            "قاعدة سابقة في نفس القائمة تجعل قاعدة لاحقة غير قابلة للوصول. "
            "القاعدة اللاحقة تظهر 0 hits."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("acl_shadowed", 0) > 0
            else Confidence.LOW
        ),
        remediation_hint=(
            "Reorder the ACL so the more specific ACE comes "
            "first. Use 'show ip access-lists' to confirm."
        ),
        remediation_hint_ar=(
            "أعد ترتيب ACL لتأتي القاعدة الأكثر تحديداً أولاً. "
            "استخدم 'show ip access-lists' للتأكيد."
        ),
    ),
    CausePattern(
        id="ntp_drift",
        title="NTP drift",
        title_ar="انحراف NTP",
        description=(
            "Device clock is more than 1 second off from the "
            "NTP server. Affects logs, certificates, BGP timers."
        ),
        description_ar=(
            "ساعة الجهاز تنحرف أكثر من ثانية عن خادم NTP. "
            "يؤثر على السجلات والشهادات ومؤقتات BGP."
        ),
        check=lambda e: (
            Confidence.HIGH if abs(e.get("ntp_offset_s", 0)) > 1.0
            else Confidence.MEDIUM if abs(e.get("ntp_offset_s", 0)) > 0.1
            else Confidence.LOW
        ),
        remediation_hint=(
            "Check 'show ntp status' and verify reachability "
            "to the configured NTP server."
        ),
        remediation_hint_ar=(
            "افحص 'show ntp status' وتحقق من الوصول لخادم NTP."
        ),
    ),
    CausePattern(
        id="power_budget",
        title="PoE budget exceeded",
        title_ar="تجاوز ميزانية PoE",
        description=(
            "Total PoE draw is greater than the supply. "
            "The switch will deny power to the lowest-priority "
            "port."
        ),
        description_ar=(
            "إجمالي استهلاك PoE أكبر من المعروض. سيمرر المفتاح "
            "رفض الطاقة للمنفذ الأقل أولوية."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("poe_over_budget")
            else Confidence.MEDIUM if e.get("poe_utilization_pct", 0) > 90
            else Confidence.LOW
        ),
        remediation_hint=(
            "Identify non-critical PoE devices and move them to "
            "another switch, or upgrade the PoE supply."
        ),
        remediation_hint_ar=(
            "حدد أجهزة PoE غير الحرجة وانقلها لمفتاح آخر، "
            "أو رقّي مصدر الطاقة."
        ),
    ),
    CausePattern(
        id="dhcp_rogue",
        title="Rogue DHCP server",
        title_ar="خادم DHCP غير مصرح",
        description=(
            "An unauthorized DHCP server is on the LAN. "
            "Symptoms: clients get the wrong gateway, "
            "snooping violations logged."
        ),
        description_ar=(
            "خادم DHCP غير مصرح موجود على الشبكة. الأعراض: "
            "العملاء يحصلون على بوابة خاطئة، انتهاكات snooping مسجلة."
        ),
        check=lambda e: (
            Confidence.HIGH if e.get("dhcp_snooping_violations", 0) > 0
            else Confidence.LOW
        ),
        remediation_hint=(
            "Use 'show ip dhcp snooping' to find the untrusted "
            "port offering DHCP, then shut it down."
        ),
        remediation_hint_ar=(
            "استخدم 'show ip dhcp snooping' لتحديد المنفذ غير الموثوق "
            "ثم أغلقه."
        ),
    ),
)


def _analyze(
    problem: str,
    problem_ar: str,
    evidence: dict[str, Any],
    symptoms: list[str] | None = None,
) -> RootCauseAnalysis:
    analysis = RootCauseAnalysis(
        problem=problem,
        problem_ar=problem_ar,
        symptoms=symptoms or [],
    )
    for pattern in _CATALOGUE:
        try:
            confidence = pattern.check(evidence)
        except Exception:  # noqa: BLE001
            confidence = Confidence.LOW
        if confidence != Confidence.LOW or evidence:
            # include even LOW confidence if there's any evidence
            if confidence == Confidence.LOW and not any(
                v for v in evidence.values() if v not in (0, "", False, None)
            ):
                continue
            analysis.causes.append(RootCause(
                pattern=pattern,
                confidence=confidence,
                evidence={
                    k: v for k, v in evidence.items()
                    if v not in (0, "", False, None)
                },
            ))
    return analysis


def analyze_link_down(
    *,
    interface: str,
    crc_errors: int = 0,
    speed_duplex_mismatch: bool = False,
    cable_diag_health: str = "good",
    stp_blocked: bool = False,
    mtu_mismatch: bool = False,
) -> RootCauseAnalysis:
    """Analyze why a single link is down or degraded."""
    return _analyze(
        problem=f"Link {interface} is down or degraded",
        problem_ar=f"الرابط {interface} متوقف أو متدهور",
        evidence={
            "crc_errors": crc_errors,
            "speed_duplex_mismatch": speed_duplex_mismatch,
            "cable_fault": cable_diag_health == "fault",
            "stp_blocked": stp_blocked,
            "mtu_mismatch": mtu_mismatch,
        },
        symptoms=[
            f"interface: {interface}",
            f"crc_errors: {crc_errors}",
            f"speed_duplex_mismatch: {speed_duplex_mismatch}",
            f"cable_diag: {cable_diag_health}",
        ],
    )


def analyze_connectivity_loss(
    *,
    src: str,
    dst: str,
    vlan_mismatch: bool = False,
    mtu_mismatch: bool = False,
    stp_blocked: bool = False,
    acl_shadowed: int = 0,
    ntp_offset_s: float = 0.0,
) -> RootCauseAnalysis:
    """Analyze why a host cannot reach another host."""
    return _analyze(
        problem=f"Connectivity loss: {src} → {dst}",
        problem_ar=f"فقدان الاتصال: {src} ← {dst}",
        evidence={
            "vlan_mismatch": vlan_mismatch,
            "vlan_mismatch_partial": vlan_mismatch,
            "mtu_mismatch": mtu_mismatch,
            "stp_blocked": stp_blocked,
            "acl_shadowed": acl_shadowed,
            "ntp_offset_s": ntp_offset_s,
        },
        symptoms=[
            f"src: {src}",
            f"dst: {dst}",
            f"vlan_mismatch: {vlan_mismatch}",
            f"mtu_mismatch: {mtu_mismatch}",
            f"stp_blocked: {stp_blocked}",
        ],
    )


def analyze_routing_down(
    *,
    peer: str,
    protocol: str = "ospf",
    ospf_area_mismatch: bool = False,
    bgp_as_mismatch: bool = False,
) -> RootCauseAnalysis:
    """Analyze why a routing neighbor is down."""
    return _analyze(
        problem=f"{protocol.upper()} peer {peer} is down",
        problem_ar=f"الجار {protocol.upper()} {peer} متوقف",
        evidence={
            "ospf_area_mismatch": ospf_area_mismatch,
            "bgp_as_mismatch": bgp_as_mismatch,
        },
        symptoms=[
            f"peer: {peer}",
            f"protocol: {protocol}",
        ],
    )


def analyze_poe(
    *,
    over_budget: bool = False,
    utilization_pct: float = 0.0,
    fault_count: int = 0,
) -> RootCauseAnalysis:
    """Analyze a PoE problem."""
    return _analyze(
        problem="PoE issue",
        problem_ar="مشكلة PoE",
        evidence={
            "poe_over_budget": over_budget,
            "poe_utilization_pct": utilization_pct,
        },
        symptoms=[
            f"over_budget: {over_budget}",
            f"utilization_pct: {utilization_pct}",
            f"fault_count: {fault_count}",
        ],
    )
