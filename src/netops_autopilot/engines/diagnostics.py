"""Phase 8 — turn a verified defect into a cause, a remedy, and a real fix.

Verification ends by naming what is wrong. Before this module that was the end
of the line: the run reported ``INCOMPLETE`` and the operator was left to work
out what to do. This is the other half — and the half most likely to become a
lie if it is built carelessly, because a diagnosis reads like knowledge whether
or not anything was observed.

Two rules hold it honest.

**Nothing is diagnosed that was not observed.** Every :class:`Diagnosis` is
built from a :class:`~netops_autopilot.engines.verification_executor.Finding`
that the verifier recorded at the moment it read the fact off a device, and
carries that finding's ledger artifact id. Diagnosis never parses the human
reason string: reconstructing a fact from prose is how a diagnosis ends up
asserting something the evidence never showed.

**Nothing is fixed that cannot be fixed safely.** Each cause states plainly
whether the platform will act on it. An SVI that is ``down/down`` is almost
always down because its VLAN has no member port — a cabling fact. The platform
can see that it is down; it cannot make someone plug a cable in, and saying
"remediated" would be the worst kind of false success. Those are returned as
``remediable=False`` with the reason and the concrete human action.

The remedy itself is not written here. :func:`remediation_nodes` selects the
**design's own IR nodes** — the same ``vlan-*`` / ``svi-*`` / ``dhcp-*`` /
``acl-*`` nodes :meth:`design_engine.render_ir` produces for a full site — so a
repair is exactly what the design intended, rendered, allowlisted, applied and
verified through the one path the platform already has. A second construction
of the same commands is how the repair and the design drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .verification_executor import Finding, FindingKind


# ---------------------------------------------------------------------------
# causes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Cause:
    """What a finding means, and what can be done about it."""

    id: str
    title: str
    title_ar: str
    remedy: str
    remedy_ar: str
    #: The platform will configure the fix itself.
    auto_remediable: bool
    #: Empty when ``auto_remediable``; otherwise why it is not, and what the
    #: operator or a human has to do. Never blank on a ``False`` — a refusal
    #: without a reason is not actionable.
    why_not: str = ""
    why_not_ar: str = ""


_CAUSES: dict[FindingKind, Cause] = {
    FindingKind.VLAN_ABSENT: Cause(
        id="VLAN_NOT_CREATED",
        title="the VLAN was never created on the device",
        title_ar="الشبكة المحلية لم تُنشأ على الجهاز",
        remedy="create the VLAN with its designed id and name",
        remedy_ar="إنشاء الشبكة المحلية بمعرّفها واسمها المصمَّم",
        auto_remediable=True),
    FindingKind.SVI_ABSENT: Cause(
        id="SVI_NOT_CREATED",
        title="the layer-3 interface for the VLAN does not exist",
        title_ar="الواجهة الطبقة الثالثة للشبكة غير موجودة",
        remedy="create the SVI with the designed gateway address",
        remedy_ar="إنشاء واجهة SVI بعنوان البوابة المصمَّم",
        auto_remediable=True),
    FindingKind.SVI_WRONG_ADDRESS: Cause(
        id="SVI_WRONG_ADDRESS",
        title="the layer-3 interface holds the wrong address",
        title_ar="الواجهة الطبقة الثالثة تحمل عنواناً خاطئاً",
        remedy="set the SVI to the designed address",
        remedy_ar="ضبط واجهة SVI على العنوان المصمَّم",
        auto_remediable=True),
    FindingKind.SVI_NOT_UP: Cause(
        id="SVI_DOWN",
        title="the layer-3 interface is administratively up but not forwarding",
        title_ar="الواجهة الطبقة الثالثة مُفعَّلة لكنها لا تمرّر",
        remedy="connect an access port in the VLAN, or correct its membership",
        remedy_ar="توصيل منفذ وصول في الشبكة، أو تصحيح عضويته",
        auto_remediable=False,
        why_not=("An SVI is protocol-down while its VLAN has no member port. "
                 "That is a physical fact: no device is cabled into the VLAN. "
                 "The platform can report it but cannot plug a cable in, and "
                 "shutting or re-addressing the interface would not make it "
                 "forward. Check the access-port cabling for this VLAN."),
        why_not_ar=("تكون واجهة SVI بروتوكولياً متوقفة ما دامت شبكتها بلا منفذ "
                    "عضو. هذه حقيقة فيزيائية: لا جهاز موصول بالشبكة. يستطيع "
                    "البرنامج الإبلاغ عنها لكنه لا يستطيع توصيل كابل، وإيقاف "
                    "الواجهة أو إعادة عنونتها لن يجعلها تمرّر. افحص توصيل "
                    "منافذ الوصول لهذه الشبكة.")),
    FindingKind.ISOLATION_NOT_ENFORCED: Cause(
        id="ISOLATION_MISSING_ACL",
        title="both networks are routed and no ACL denies the traffic",
        title_ar="كلتا الشبكتين مُوجَّهة ولا توجد قائمة وصول تمنع المرور",
        remedy="apply the designed access-list denying this pair",
        remedy_ar="تطبيق قائمة الوصول المصمَّمة لمنع هذا الزوج",
        auto_remediable=True),
    FindingKind.DHCP_POOL_MISSING: Cause(
        id="DHCP_POOL_ABSENT",
        title="no DHCP pool serves this network",
        title_ar="لا يوجد نطاق DHCP يخدم هذه الشبكة",
        remedy="create the designed DHCP pool",
        remedy_ar="إنشاء نطاق DHCP المصمَّم",
        auto_remediable=True),
    FindingKind.DHCP_POOL_WRONG_NETWORK: Cause(
        id="DHCP_POOL_WRONG_NETWORK",
        title="the DHCP pool serves the wrong network",
        title_ar="نطاق DHCP يخدم شبكة خاطئة",
        remedy="correct the pool to the designed network",
        remedy_ar="تصحيح النطاق إلى الشبكة المصمَّمة",
        auto_remediable=True),
    FindingKind.DNS_SERVER_MISSING: Cause(
        id="DHCP_POOL_NO_RESOLVERS",
        title="the DHCP pool hands out no resolver",
        title_ar="نطاق DHCP لا يوزّع أي خادم أسماء",
        remedy="add the resolvers the operator supplied to the pool",
        remedy_ar="إضافة خوادم الأسماء التي قدّمها المشغّل إلى النطاق",
        # True in principle: the platform can express the fix. Whether it can
        # on THIS finding depends on the operator having supplied resolvers,
        # and that is decided per finding by _fix_nodes_for — which returns no
        # nodes and a reason when there is nothing to write. ``auto_remediable``
        # describes the kind; only ``Diagnosis.remediable`` describes the case.
        auto_remediable=True),
    FindingKind.NO_DEFAULT_ROUTE: Cause(
        id="NO_DEFAULT_ROUTE",
        title="there is no route to anywhere outside the local networks",
        title_ar="لا يوجد مسار إلى أي مكان خارج الشبكات المحلية",
        remedy="install a default route via the provider's next hop",
        remedy_ar="تركيب مسار افتراضي عبر القفزة التالية لدى المزوّد",
        auto_remediable=False,
        why_not=("The next hop is not known from evidence. Inventing one would "
                 "black-hole the site's egress, which is worse than having no "
                 "route. With a DHCP WAN handoff the provider installs it — if "
                 "it is absent the handoff itself is not up. Supply the "
                 "provider's next hop, or restore the WAN circuit."),
        why_not_ar=("القفزة التالية غير معروفة من دليل. اختلاقها سيُسقط مرور "
                    "الموقع بالكامل، وهو أسوأ من غياب المسار. مع تسليم WAN عبر "
                    "DHCP يركّبها المزوّد — فإن غابت فالتسليم نفسه غير قائم. "
                    "زوّد القفزة التالية للمزوّد، أو أعِد دائرة WAN.")),
}


# ---------------------------------------------------------------------------
# diagnosis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Diagnosis:
    """One proven defect, its cause, and whether the platform will act.

    ``remediable`` is derived from ``fix_nodes`` alone: a diagnosis is
    actionable if and only if it names design nodes to apply. Keeping a
    separate flag is how the two come apart and the operator is told "not
    remediable" with no reason, or "remediable" with nothing to send.
    """

    finding: Finding
    cause: Cause
    #: The design node ids that would repair it. Empty when not remediable.
    fix_nodes: tuple[str, ...] = ()
    #: Why it will not be fixed. Set per finding, because some causes are
    #: remediable only under conditions the finding knows about.
    not_remediable: str = ""
    not_remediable_ar: str = ""

    def __post_init__(self) -> None:
        # Enforced, not documented. A refusal with no reason is not
        # actionable, and this is the shape of failure that is easy to
        # introduce and easy to miss.
        if not self.fix_nodes and not self.not_remediable:
            raise ValueError(
                f"{self.cause.id} on {self.finding.zone} is not remediable "
                f"but gives no reason — a refusal the operator cannot act on")

    @property
    def remediable(self) -> bool:
        return bool(self.fix_nodes)

    def render(self, lang: str = "en") -> str:
        f, c = self.finding, self.cause
        where = f" on {f.device_ref}" if f.device_ref else ""
        if lang == "ar":
            head = f"[{c.id}] {c.title_ar} — {f.zone}{where}"
            return head + ("\n" + ("  الإصلاح: " + c.remedy_ar
                                   if self.remediable else
                                   "  لا يمكن إصلاحه آلياً: " + self.not_remediable_ar))
        head = f"[{c.id}] {c.title} — {f.zone}{where}"
        return head + ("\n" + ("  remedy: " + c.remedy
                               if self.remediable else
                               "  not auto-remediable: " + self.not_remediable))


_NO_RESOLVERS = (
    "The operator supplied no DNS resolvers, so there is nothing to write. "
    "Pointing clients at a public resolver they never chose would send their "
    "queries somewhere unapproved.",
    "لم يقدّم المشغّل أي خوادم أسماء، لذا لا يوجد ما يُكتب. توجيه العملاء إلى "
    "خادم عام لم يختاروه سيُرسل استعلاماتهم إلى جهة غير معتمدة.")


def _fix_nodes_for(finding: Finding, *,
                   dns_available: bool) -> tuple[tuple[str, ...], str, str]:
    """The design nodes that repair this finding, or why none do.

    Returns ``(node_ids, why_not, why_not_ar)``. Exactly one side is
    populated: either there is a fix, or there is a reason there is not.
    """
    """The design's own node ids that repair this finding.

    Returning ids rather than commands is deliberate: the nodes are looked up
    in the design IR, so a repair can never contain a line the design did not
    already intend.
    """
    kind, zone = finding.kind, finding.zone
    if kind is FindingKind.VLAN_ABSENT:
        return (f"vlan-{zone}-{finding.vlan_id}",), "", ""
    if kind in (FindingKind.SVI_ABSENT, FindingKind.SVI_WRONG_ADDRESS):
        return (f"svi-{zone}",), "", ""
    if kind in (FindingKind.DHCP_POOL_MISSING,
                FindingKind.DHCP_POOL_WRONG_NETWORK):
        return (f"dhcp-{zone}",), "", ""
    if kind is FindingKind.DNS_SERVER_MISSING:
        # The resolvers are one line inside the pool, so the pool node carries
        # the fix — but only if the operator actually supplied resolvers.
        if dns_available:
            return (f"dhcp-{zone}",), "", ""
        return (), _NO_RESOLVERS[0], _NO_RESOLVERS[1]
    if kind is FindingKind.ISOLATION_NOT_ENFORCED:
        # finding.zone is "src->dst"; the ACL lives on the source zone.
        src = zone.split("->")[0]
        return ((f"acl-deny-{zone}", f"acl-permit-{src}", f"acl-apply-{src}"),
                "", "")
    cause = _CAUSES.get(kind)
    if cause is not None and not cause.auto_remediable:
        return (), cause.why_not, cause.why_not_ar
    return (), (f"no repair is defined for {kind.value}",
                f"لا يوجد إصلاح معرَّف لـ {kind.value}")


def diagnose(
    findings: Iterable[Finding],
    *,
    dns_available: bool = False,
) -> tuple[Diagnosis, ...]:
    """Classify proven defects. Deterministic, and de-duplicated.

    The same zone appears in several tests (``users->users``, ``users->wan``),
    so one missing SVI is reported by many. Diagnosing each copy would send the
    same fix several times and would overstate how much is broken.
    """
    seen: dict[tuple, Diagnosis] = {}
    for f in findings:
        cause = _CAUSES.get(f.kind)
        if cause is None:
            # A finding with no cause is a gap in THIS module, not in the
            # network. Reported rather than silently dropped, because a defect
            # that vanishes between verification and diagnosis is worse than
            # one that is merely unexplained.
            cause = Cause(id="UNCLASSIFIED", title="unclassified defect",
                          title_ar="عطل غير مصنَّف",
                          remedy="inspect the cited evidence",
                          remedy_ar="افحص الدليل المشار إليه",
                          auto_remediable=False,
                          why_not=f"no cause is defined for {f.kind.value}",
                          why_not_ar=f"لا يوجد سبب معرَّف لـ {f.kind.value}")
        nodes, why, why_ar = _fix_nodes_for(f, dns_available=dns_available)
        key = (f.kind.value, f.device_ref, f.zone, f.vlan_id)
        if key not in seen:
            seen[key] = Diagnosis(finding=f, cause=cause, fix_nodes=nodes,
                                  not_remediable=why or cause.why_not,
                                  not_remediable_ar=why_ar or cause.why_not_ar)
    return tuple(seen.values())


def remediation_nodes(
    diagnoses: Iterable[Diagnosis],
    ir_of: dict,
) -> dict:
    """Select the design's own IR nodes that repair the remediable diagnoses.

    ``ir_of`` is the ``{device_ref: ConfigIR}`` map the design engine already
    produced. Nodes are looked up by id, so the repair is a subset of the
    design — never a freshly authored configuration.

    A diagnosis whose node is absent from the design is reported by returning it
    in ``missing`` rather than being quietly skipped: that means the design and
    the diagnosis disagree, and the operator is owed that fact.
    """
    selected: dict[str, list] = {}
    missing: list[str] = []
    wanted: dict[str, set[str]] = {}
    for d in diagnoses:
        if not d.remediable:
            continue
        device = d.finding.device_ref
        for nid in d.fix_nodes:
            wanted.setdefault(device, set()).add(nid)
    for device, ids in wanted.items():
        ir = ir_of.get(device)
        have = {n.node_id: n for n in (ir.nodes if ir is not None else ())}
        picked: list = []
        for nid in sorted(ids):
            node = have.get(nid)
            if node is None:
                missing.append(f"{device}:{nid}")
                continue
            picked.append(node)
        # An ACL needs its denies, its trailing permit and its application to
        # be coherent on their own; a partial ACL could black-hole the zone.
        # The design emits all three, so take them together or not at all.
        for src in {n.node_id.split("-", 2)[2].rsplit("-", 1)[0]
                    for n in picked if n.node_id.startswith("acl-apply-")}:
            for companion in (f"acl-permit-{src}", f"acl-apply-{src}"):
                if companion in have and not any(
                        n.node_id == companion for n in picked):
                    picked.append(have[companion])
        if picked:
            selected[device] = picked
    return {"nodes": selected, "missing": tuple(sorted(missing))}
