"""Smart Recommendations — the 30-year expert's "you should also...".

When a junior asks "should I add a trunk here?", a senior
engineer answers with three follow-ups:

1. "Yes, but you also need a spanning-tree guard or you'll
    loop the campus."
2. "Use 802.1Q encapsulation on both sides; mismatched ISL
   on the legacy 6500 will silently fail."
3. "Capture a snapshot first; this is a high-risk change."

This module turns that experience into a typed, deterministic
recommendation engine. Every recommendation is a
:class:`Recommendation` with an id, a category, a severity,
the trigger condition, and the prescribed action.

Design contract:

* **No LLM** — every recommendation is a
  :class:`RecommendationPattern` row in the catalogue. There
  is no generation, only matching.
* **Typed** — every recommendation carries
  :class:`RecommendationCategory` (BEST_PRACTICE / SECURITY /
  PERFORMANCE / RELIABILITY) and :class:`Severity` (INFO /
  ADVISED / REQUIRED).
* **Bilingual** — rendering in English or Arabic.
* **Always multi** — the engine never returns a single
  recommendation. It returns all that match, ranked by
  severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    __test__ = False

    INFO = "INFO"               # nice to know
    ADVISED = "ADVISED"         # recommended
    REQUIRED = "REQUIRED"       # must do


class RecommendationCategory(str, Enum):
    __test__ = False

    BEST_PRACTICE = "BEST_PRACTICE"
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    RELIABILITY = "RELIABILITY"
    COMPLIANCE = "COMPLIANCE"


@dataclass(frozen=True)
class RecommendationPattern:
    __test__ = False

    id: str
    title: str
    title_ar: str
    body: str
    body_ar: str
    category: RecommendationCategory
    severity: Severity
    triggers: tuple[tuple[str, str], ...] = ()
    # A trigger is (key, expected_value_as_str). All must match.


@dataclass
class Recommendation:
    __test__ = False

    pattern: RecommendationPattern
    matched: dict[str, str] = field(default_factory=dict)


@dataclass
class RecommendationReport:
    __test__ = False

    context_label: str
    recommendations: list[Recommendation] = field(default_factory=list)

    @property
    def required_count(self) -> int:
        return sum(
            1 for r in self.recommendations
            if r.pattern.severity == Severity.REQUIRED
        )

    @property
    def advised_count(self) -> int:
        return sum(
            1 for r in self.recommendations
            if r.pattern.severity == Severity.ADVISED
        )

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return self._render_ar()
        return self._render_en()

    def _render_en(self) -> str:
        if not self.recommendations:
            return f"No recommendations for {self.context_label}."
        order = [Severity.REQUIRED, Severity.ADVISED, Severity.INFO]
        recs = sorted(
            self.recommendations,
            key=lambda r: order.index(r.pattern.severity),
        )
        lines = [f"Recommendations for {self.context_label}:"]
        for r in recs:
            sev = r.pattern.severity.value
            cat = r.pattern.category.value
            lines.append(f"  [{sev} / {cat}] {r.pattern.title}")
            lines.append(f"    {r.pattern.body}")
        return "\n".join(lines)

    def _render_ar(self) -> str:
        if not self.recommendations:
            return f"لا توجد توصيات لـ {self.context_label}."
        order = [Severity.REQUIRED, Severity.ADVISED, Severity.INFO]
        recs = sorted(
            self.recommendations,
            key=lambda r: order.index(r.pattern.severity),
        )
        lines = [f"توصيات لـ {self.context_label}:"]
        for r in recs:
            sev = r.pattern.severity.value
            cat = r.pattern.category.value
            lines.append(f"  [{sev} / {cat}] {r.pattern.title_ar}")
            lines.append(f"    {r.pattern.body_ar}")
        return "\n".join(lines)


# ---------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------


_CATALOGUE: tuple[RecommendationPattern, ...] = (
    RecommendationPattern(
        id="trunk-snapshot-before",
        title="Capture a snapshot before adding a trunk",
        title_ar="التقط لقطة قبل إضافة ترانك",
        body=(
            "A trunk change is medium-risk. Capture the "
            "running-config as a snapshot first so rollback "
            "is one 'configure replace' away."
        ),
        body_ar=(
            "تغيير الترانك متوسط الخطورة. التقط snapshot "
            "للإعدادات الحالية ليكون التراجع بأمر 'configure replace' واحد."
        ),
        category=RecommendationCategory.RELIABILITY,
        severity=Severity.ADVISED,
        triggers=(("action", "add_trunk"),),
    ),
    RecommendationPattern(
        id="stp-guard-before-trunk",
        title="Enable BPDU guard on access ports before turning on a trunk",
        title_ar="فعّل BPDU guard على منافذ الوصول قبل تشغيل الترانك",
        body=(
            "Without BPDU guard, an attacker can plug a "
            "rogue switch into an access port and become "
            "the STP root. Enable 'spanning-tree portfast "
            "bpduguard default' before adding a trunk."
        ),
        body_ar=(
            "بدون BPDU guard، يمكن لمهاجم توصيل سويتش غير مصرح "
            "في منفذ وصول ويصبح جذر STP. فعّل 'spanning-tree "
            "portfast bpduguard default' قبل إضافة الترانك."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.REQUIRED,
        triggers=(("action", "add_trunk"),),
    ),
    RecommendationPattern(
        id="dhcp-snoop-before-vlan",
        title="Enable DHCP snooping on user VLANs",
        title_ar="فعّل DHCP snooping على VLANs المستخدمين",
        body=(
            "Without DHCP snooping, a rogue DHCP server can "
            "hand out wrong gateways and DNS. Enable it on "
            "every user VLAN before adding the SVI."
        ),
        body_ar=(
            "بدون DHCP snooping، يمكن لخادم DHCP غير مصرح "
            "توزيع بوابات و DNS خاطئة. فعّله على كل VLAN مستخدمين."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.ADVISED,
        triggers=(("action", "add_svi"),),
    ),
    RecommendationPattern(
        id="port-channel-lacp",
        title="Use LACP, not 'on', for port-channels",
        title_ar="استخدم LACP لا 'on' للـport-channels",
        body=(
            "LACP actively negotiates the bundle and will "
            "drop a mismatched member. 'channel-group X mode "
            "on' is a one-way handshake and is the #1 cause "
            "of 'one side up, other side down' mysteries."
        ),
        body_ar=(
            "LACP يفاوض نشطاً على الحزمة ويسقط العضو غير المتطابق. "
            "'channel-group X mode on' مصافحة أحادية وهو السبب "
            "الأول لـ'طرف up، طرف down'."
        ),
        category=RecommendationCategory.BEST_PRACTICE,
        severity=Severity.ADVISED,
        triggers=(("action", "add_port_channel"),),
    ),
    RecommendationPattern(
        id="ntp-on-everything",
        title="Configure NTP on every device",
        title_ar="اضبط NTP على كل جهاز",
        body=(
            "Logs are useless if the device clock is wrong. "
            "Configure 'ntp server <auth-source>' before "
            "deploying."
        ),
        body_ar=(
            "السجلات لا فائدة منها إذا كانت ساعة الجهاز خاطئة. "
            "اضبط 'ntp server <مصدر موثوق>' قبل النشر."
        ),
        category=RecommendationCategory.RELIABILITY,
        severity=Severity.REQUIRED,
        triggers=(("action", "initial_deploy"),),
    ),
    RecommendationPattern(
        id="login-banner",
        title="Set a legal login banner",
        title_ar="اضبط banner قانوني عند الدخول",
        body=(
            "A login banner is a legal requirement in many "
            "jurisdictions. 'banner login' should reference "
            "your acceptable-use policy."
        ),
        body_ar=(
            "Banner تسجيل الدخول متطلب قانوني في عدة دول. "
            "'banner login' يجب أن يذكر سياسة الاستخدام المقبول."
        ),
        category=RecommendationCategory.COMPLIANCE,
        severity=Severity.ADVISED,
        triggers=(("action", "initial_deploy"),),
    ),
    RecommendationPattern(
        id="ssh-v2-only",
        title="Disable SSHv1 and Telnet",
        title_ar="عطّل SSHv1 و Telnet",
        body=(
            "SSHv1 has known protocol-level attacks. Telnet "
            "sends passwords in clear. Use 'ip ssh version 2' "
            "and 'line vty 0 15 / transport input ssh'."
        ),
        body_ar=(
            "SSHv1 معروف بهجمات على مستوى البروتوكول. "
            "Telnet يرسل كلمات السر بدون تشفير. "
            "استخدم 'ip ssh version 2' و 'line vty 0 15 / transport input ssh'."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.REQUIRED,
        triggers=(("action", "initial_deploy"),),
    ),
    RecommendationPattern(
        id="console-timeout",
        title="Set a console timeout",
        title_ar="اضبط مهلة على console",
        body=(
            "An unattended console is an attack surface. "
            "'line console 0 / exec-timeout 5 0' logs out "
            "after 5 minutes idle."
        ),
        body_ar=(
            "كونسول غير مراقب سطح هجوم. "
            "'line console 0 / exec-timeout 5 0' يخرج بعد 5 دقائق خمول."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.ADVISED,
        triggers=(("action", "initial_deploy"),),
    ),
    RecommendationPattern(
        id="storm-control",
        title="Enable storm control on user access ports",
        title_ar="فعّل storm control على منافذ وصول المستخدمين",
        body=(
            "A misbehaving NIC can broadcast-storm the LAN. "
            "Storm control drops the port when it exceeds a "
            "configured rate."
        ),
        body_ar=(
            "NIC معطوب قد يبث عاصفة على LAN. "
            "Storm control يقطع المنفذ عند تجاوز المعدل المحدد."
        ),
        category=RecommendationCategory.RELIABILITY,
        severity=Severity.ADVISED,
        triggers=(("action", "add_trunk"),),
    ),
    RecommendationPattern(
        id="uplink-portfast-disable",
        title="Disable portfast on trunk / uplink ports",
        title_ar="عطّل portfast على منافذ الترانك / uplink",
        body=(
            "Portfast is for access ports only. On a trunk it "
            "skips the listening/learning states and will "
            "briefly loop the VLAN."
        ),
        body_ar=(
            "Portfast مخصص لمنافذ الوصول فقط. على الترانك يتخطى "
            "مرحلتي listening/learning ويسبب حلقة VLAN مؤقتة."
        ),
        category=RecommendationCategory.RELIABILITY,
        severity=Severity.REQUIRED,
        triggers=(("action", "add_trunk"),),
    ),
    RecommendationPattern(
        id="vlan-prune-allowed",
        title="Restrict the trunk to only the VLANs it needs",
        title_ar="قيد الترانك على VLANs الضرورية فقط",
        body=(
            "Allowing 1-4094 on a trunk is a security risk "
            "and a performance risk. 'switchport trunk "
            "allowed vlan 10,20,30' is the rule."
        ),
        body_ar=(
            "السماح بـ 1-4094 على الترانك مخاطرة أمنية وأدائية. "
            "'switchport trunk allowed vlan 10,20,30' هو القاعدة."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.ADVISED,
        triggers=(("action", "add_trunk"),),
    ),
    RecommendationPattern(
        id="l3-ibgp-loopback",
        title="Use Loopback0 for iBGP peer IP",
        title_ar="استخدم Loopback0 لعنوان iBGP",
        body=(
            "Loopback0 never goes down. The iBGP session "
            "survives a physical-interface failure. Always "
            "'neighbor <peer> update-source Loopback0'."
        ),
        body_ar=(
            "Loopback0 لا يتوقف أبداً. جلسة iBGP تبقى بعد "
            "فشل فيزيائي. دائماً 'neighbor <peer> update-source "
            "Loopback0'."
        ),
        category=RecommendationCategory.BEST_PRACTICE,
        severity=Severity.ADVISED,
        triggers=(("action", "add_bgp"),),
    ),
    RecommendationPattern(
        id="ospf-bfd",
        title="Enable BFD for OSPF fast-failure",
        title_ar="فعّل BFD لكشف فشل OSPF السريع",
        body=(
            "OSPF hello/dead timers are 10/40 by default — "
            "that is a 40-second outage window. BFD detects "
            "a peer failure in <1s."
        ),
        body_ar=(
            "مؤقتات OSPF الافتراضية 10/40 — أي 40 ثانية انقطاع. "
            "BFD يكتشف فشل الجار في أقل من ثانية."
        ),
        category=RecommendationCategory.PERFORMANCE,
        severity=Severity.ADVISED,
        triggers=(("action", "add_ospf"),),
    ),
    RecommendationPattern(
        id="copp-policy",
        title="Apply a CoPP policy on the supervisor",
        title_ar="طبّق CoPP على المعالج",
        body=(
            "Without CoPP, a flood of ARP or BGP packets "
            "can pin the CPU. Apply a hardware-validated "
            "control-plane policy."
        ),
        body_ar=(
            "بدون CoPP، فيضان ARP أو BGP قد يوقف المعالج. "
            "طبّق policy على control plane."
        ),
        category=RecommendationCategory.SECURITY,
        severity=Severity.ADVISED,
        triggers=(("action", "initial_deploy"),),
    ),
)


def _match(pattern: RecommendationPattern, context: dict[str, str]) -> bool:
    for key, expected in pattern.triggers:
        if context.get(key, "") != expected:
            return False
    return True


def recommend(
    context_label: str,
    context: dict[str, str],
) -> RecommendationReport:
    """Return all recommendations that match ``context``.

    ``context`` is a free-form dict of key/value pairs. A
    pattern triggers when all of its ``(key, expected)`` pairs
    match.
    """
    rep = RecommendationReport(context_label=context_label)
    for pattern in _CATALOGUE:
        if _match(pattern, context):
            rep.recommendations.append(
                Recommendation(pattern=pattern, matched=dict(context))
            )
    return rep


def recommend_for_action(
    action: str,
    context_label: str = "",
) -> RecommendationReport:
    """Shortcut: recommend for a single action like 'add_trunk'."""
    if not context_label:
        context_label = action
    return recommend(context_label, {"action": action})
