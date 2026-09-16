"""
Intent Parser — يحول وصف الإنسان إلى intent منظم، بدون تخمين
القاعدة: إذا النص لا يطابق نوع معروف، نطلب اختيار صريح — صفر تخمين
"""
import re
from typing import Dict, List, Optional, Any
from pydantic import BaseModel

class VlanIntent(BaseModel):
    id: int
    name: str
    purpose: str  # إدارة / مستخدمين / ضيوف / خوادم / ...
    subnet: Optional[str] = None
    dhcp: bool = True

class Intent(BaseModel):
    networkName: str = "NET-AUTO-01"
    preset: str  # small-office / campus / branch / data-center / custom
    routing: str = "static"  # static / ospf
    hardening: str = "standard"  # standard / hardened
    vlans: List[VlanIntent]
    ntpServer: str = "pool.ntp.org"
    dnsServers: List[str] = ["8.8.8.8", "1.1.1.1"]
    rawText: str
    confidence: float
    explicitChoices: Dict[str, Any]

PRESETS = {
    "small-office": {
        "vlans": [{"id": 10, "name": "MGMT", "purpose": "إدارة"}, {"id": 20, "name": "USERS", "purpose": "مستخدمين"}, {"id": 30, "name": "GUEST", "purpose": "ضيوف"}],
        "routing": "static"
    },
    "campus": {
        "vlans": [{"id": 10, "name": "MGMT", "purpose": "إدارة"}, {"id": 20, "name": "USERS", "purpose": "مستخدمين"}, {"id": 30, "name": "SERVERS", "purpose": "خوادم"}, {"id": 40, "name": "WIFI", "purpose": "لاسلكي"}, {"id": 99, "name": "GUEST", "purpose": "ضيوف"}],
        "routing": "ospf"
    },
    "branch": {
        "vlans": [{"id": 10, "name": "MGMT", "purpose": "إدارة"}, {"id": 20, "name": "BRANCH-USERS", "purpose": "مستخدمين"}],
        "routing": "static"
    },
    "data-center": {
        "vlans": [{"id": 10, "name": "MGMT", "purpose": "إدارة"}, {"id": 100, "name": "SERVERS", "purpose": "خوادم"}, {"id": 200, "name": "STORAGE", "purpose": "تخزين"}],
        "routing": "ospf"
    }
}

class IntentParser:
    def parse(self, text: str) -> Dict[str, Any]:
        raw = text.strip()
        lower = raw.lower()

        # كشف preset بالكلمات المفتاحية — بدون تخمين ثقيل، مطابقات واضحة فقط
        preset = None
        if any(k in lower for k in ["small", "مكتب صغير", "office 5", "10 users"]):
            preset = "small-office"
        elif any(k in lower for k in ["campus", "جامعة", "حرم", "مبنى كبير", "كبير"]):
            preset = "campus"
        elif any(k in lower for k in ["branch", "فرع", "فروع"]):
            preset = "branch"
        elif any(k in lower for k in ["data center", "مركز بيانات", "dc "]):
            preset = "data-center"

        if not preset:
            return {
                "ok": False,
                "error": "لم يتطابق نصك مع أي نوع معرّف — صفر تخمين يعني أنك تختار بنفسك:",
                "choices": list(PRESETS.keys()),
                "hint": "اختر أحد: small-office, campus, branch, data-center أو صف VLANs يدوياً"
            }

        base = PRESETS[preset]
        # VLANs إضافية يذكرها المستخدم: ابحث عن VLAN <id> <name>
        extra_vlans = []
        for m in re.finditer(r"vlan\s*(\d+)\s*(\w+)", lower):
            extra_vlans.append({"id": int(m.group(1)), "name": m.group(2).upper(), "purpose": "مخصص"})

        vlans = base["vlans"] + extra_vlans

        # routing / hardening من النص
        routing = "ospf" if "ospf" in lower else base["routing"]
        hardening = "hardened" if any(k in lower for k in ["hardened", "محصن", "c hardening", "cis"]) else "standard"

        intent = Intent(
            networkName="NET-" + preset.upper().replace("-", "_"),
            preset=preset,
            routing=routing,
            hardening=hardening,
            vlans=[VlanIntent(**v) for v in vlans],
            rawText=raw,
            confidence=0.92 if preset else 0.0,
            explicitChoices={"preset": preset, "routing": routing, "hardening": hardening}
        )

        return {
            "ok": True,
            "intent": intent.model_dump(),
            "preset": preset,
            "confidence": 0.92
        }

parser = IntentParser()
