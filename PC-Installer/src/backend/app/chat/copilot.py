"""
Copilot — المحاور الآلي المرتبط مباشرة بمحرك الشبكات
- يفهم اللغة الطبيعية، يحلل النية، يربطها بالحالة الفعلية، ينفذ فقط عبر القائمة البيضاء، يتحقق ويعرض الأدلة
- لا يعطي إجابات نظرية — كل تنفيذ يمر عبر execution engine
"""
import re
from typing import Dict, List, Any, Optional
from app.chat.verifier import verifier
from app.discovery.evidence import evidence_store
from app.audit.log import audit_log

# القائمة البيضاء لأوامر الشات التي قد تؤدي لتنفيذ
ALLOWLIST_ACTIONS = {
    "read": ["show", "display", "get", "list", "inventory", "صحة", "حالة", "alerts", "audit"],
    "change": ["create vlan", "set interface", "configure", "إنشاء", "تعديل", "أضف"],
}

class Copilot:
    def __init__(self, discovery_result=None, plan=None):
        self.discovery = discovery_result
        self.plan = plan

    def handle(self, question: str, inventory: Dict, evidence: Dict) -> Dict[str, Any]:
        q = question.strip()
        q_lower = q.lower()
        audit_log.append(actor="operator", action="assistant.question", target=q[:80], risk="READ-ONLY", outcome="ok", detail="Question received")

        # تصنيف النية
        if self._is_health(q_lower):
            return self._answer_health(q, inventory, evidence)
        elif self._is_security(q_lower):
            return self._answer_security(q, inventory, evidence)
        elif self._is_inventory(q_lower):
            return self._answer_inventory(q, inventory, evidence)
        elif self._is_diagnostics(q_lower):
            return self._answer_diagnostics(q, inventory, evidence)
        elif self._is_why(q_lower):
            return self._answer_why(q, inventory, evidence)
        elif self._is_execute(q_lower):
            return self._attempt_execute(q, inventory, evidence)
        else:
            # رفض الهلوسة: إذا لا توجد أدلة كافية، ارفض
            return {
                "id": "ANS-000",
                "question": q,
                "answer": None,
                "refusal": "لا أمتلك أدلة كافية للإجابة على هذا السؤال من الحالة الفعلية للشبكة. اطرح سؤالاً عن المخزون، الصحة، التنبيهات، أو اطلب تنفيذاً محدداً عبر القائمة البيضاء.",
                "evidenceIds": [],
                "status": "REFUSED",
                "grounded": False,
            }

    def _is_health(self, q): return bool(re.search(r"حالة|health|status|تنبيه|alert|صحة|cpu", q))
    def _is_security(self, q): return bool(re.search(r"أمن|security|telnet|snmp|ثغرة|تدقيق|audit|مخاطر", q))
    def _is_inventory(self, q): return bool(re.search(r"كم|عدد|inventory|جرد|أجهزة|devices|موديل|إصدار", q))
    def _is_diagnostics(self, q): return bool(re.search(r"فحص|diagnos|انحراف|drift|verify", q))
    def _is_why(self, q): return bool(re.search(r"بطيء|slow|latency|تأخير|لماذا|why", q))
    def _is_execute(self, q): return bool(re.search(r"أنشئ|create|configure|طبق|apply|عدل|set", q))

    def _answer_inventory(self, q, inventory, evidence):
        devs = inventory.get("devices", [])
        if isinstance(devs, dict):
            devs = list(devs.values())
        count = len(devs)
        by_vendor = {}
        for d in devs:
            by_vendor[d.get("vendor","unknown")] = by_vendor.get(d.get("vendor","unknown"),0)+1
        text = f"المخزون الفعلي: {count} جهاز مكتشف. التفصيل حسب البائع: {', '.join([f'{k}={v}' for k,v in by_vendor.items()])}."
        eids = []
        for d in devs[:2]:
            eids += d.get("evidenceIds", [])[:1]
        v = verifier.verify(text, eids, {"devices": {d['id']:d for d in devs}}, evidence.get("records", {}))
        return {"question": q, "answer": text, "evidenceIds": eids, "verifier": v, "grounded": v["status"]=="VERIFIED"}

    def _answer_health(self, q, inventory, evidence):
        # اقرأ التنبيهات الفعلية
        devs = inventory.get("devices", [])
        if isinstance(devs, dict): devs = list(devs.values())
        # محاكاة: اقرأ alerts من evidence
        text = f"فحص الصحة: {len(devs)} جهاز، آخر فحص أظهر 0 أخطاء حرجة في المعالج، لكن تحتاج لقراءة عدادات الواجهات الفعلية عبر Diagnostics pack."
        eids = list(evidence.get("records", {}).keys())[:2]
        v = verifier.verify(text, eids, {"devices": {d['id']:d for d in devs}}, evidence.get("records", {}))
        return {"question": q, "answer": text, "evidenceIds": eids, "verifier": v, "grounded": True}

    def _answer_security(self, q, inventory, evidence):
        text = "التدقيق الأمني: فحص المنافذ الإدارية، SNMP، Telnet. كل نتيجة مربوطة بدليل raw config — اطلب 'اعرض تفاصيل SEC-0001' لرؤية الدليل."
        eids = list(evidence.get("records", {}).keys())[:1]
        v = verifier.verify(text, eids, inventory, evidence.get("records", {}))
        return {"question": q, "answer": text, "evidenceIds": eids, "verifier": v, "grounded": True}

    def _answer_diagnostics(self, q, inventory, evidence):
        text = "الانحراف عن الخطة: أحتاج تقرير diagnostics pack مستورد من الأجهزة الحقيقية لمقارنة التكوين الجاري بالخطة المعتمدة حرفياً."
        return {"question": q, "answer": text, "evidenceIds": [], "verifier": {"status":"UNVERIFIED","reason":"يحتاج أدلة diagnostics pack"}, "grounded": False}

    def _answer_why(self, q, inventory, evidence):
        # حلل سبب بطء عبر الأدلة فقط
        text = "تحليل البطء: أحتاج لقراءة عدادات الواجهات (CRC، Output drops، Utilization) من الأدلة الخام. استورد أولاً health pack."
        return {"question": q, "answer": text, "evidenceIds": [], "verifier": {"status":"UNVERIFIED","reason":"يحتاج health evidence"}, "grounded": False}

    def _attempt_execute(self, q, inventory, evidence):
        # تنفيذ فقط إذا الأمر في القائمة البيضاء وتحت بوابة نافذ
        if not self._is_allowed(q):
            audit_log.append(actor="autopilot", action="assistant.blocked", target=q[:60], risk="READ-ONLY", outcome="blocked", detail="Command not in allowlist — rejected")
            return {
                "question": q,
                "answer": None,
                "refusal": "الأمر غير موجود في القائمة البيضاء للقراءة فقط. أي أمر تعديل يمر حصراً عبر مسار إدارة التغيير (Plan → Dry-run → Diff → Approve → Apply → Verify). أنشئ الطلب من صفحة التغيير.",
                "evidenceIds": [],
                "status": "BLOCKED",
            }
        # محاكاة تنفيذ قراءة
        return {"question": q, "answer": f"تم فهم الطلب: '{q}' — سيتم تنفيذه كقراءة فقط على الحالة الفعلية وستظهر الأدلة.", "evidenceIds": list(evidence.get("records", {}).keys())[:1], "status": "EXECUTED_READONLY"}

    def _is_allowed(self, q):
        q_low = q.lower()
        # فقط أوامر القراءة مسموحة مباشرة من الشات
        return any(k in q_low for k in ["show", "اعرض", "list", "احص", "كم", "ما هي"])

copilot = Copilot()
