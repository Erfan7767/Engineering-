# NetOps Autopilot REAL v2.0 — مهندس الشبكات الآلي الحقيقي

> **المصدر الأصلي المسحوب:** https://netops-autopilot-m6r65hk.rork.app — تم سحبه كاملاً بدون نقص (index-BBAnUz2e.js 943KB) ثم **ترقيته إلى نظام حقيقي فعلي** يعمل على الأجهزة الحقيقية.

## 🎯 ما تم إنجازه — ترقية عميقة فائقة

حولنا النموذج المختبري المحاكي (Lab) إلى **برنامج حقيقي فعلي بديل لمهندس الشبكات** يحقق دورة العمل الكاملة:

### دورة العمل الحقيقية (كما طلبت)

```
إنسان: يركب الأجهزة + يكبلها + يغذيها بالطاقة + يوصل جهازاً واحداً بالكمبيوتر
   ↓
برنامج: يكتشف الأجهزة الحقيقية المتصلة فعلياً (LLDP/CDP crawl) + يجمع المعلومات الفعلية + ينشئ خريطة شبكية فعلية/منطقية
   ↓
برنامج: يسأل "ما نوع الشبكة التي تريدها؟"
   ↓
إنسان: يدخل وصف الشبكة (مثلاً: campus + OSPF + hardened)
   ↓
برنامج: يحول المتطلبات → تصميم شبكي → تنفيذ فعلي على الأجهزة الحقيقية (VLANs, Routing, Interfaces, IPs, Services, Security...)
   ↓
برنامج: يتحقق فعلياً (Verification) — يقرأ الحالة بعد التنفيذ ويقارن بالمطلوب — لا يعتبر الإرسال نجاحاً
   ↓
إنسان: يتحكم بالشبكة عبر Chat ذكي مرتبط مباشرة بالمحرك والتنفيذ الفعلي
```

**المبادئ الصارمة المطبقة:**
- ✅ **لا هلوسة** — كل جملة تمر عبر `claim_verifier` قبل العرض
- ✅ **لا تخمين** — إذا النص لا يطابق preset معروف → يطلب اختيار صريح
- ✅ **لا تجاهل** — أي فشل يُعلن `failures[]` ولا يُدمج مع الناجح
- ✅ **لا عشوائية** — كل خطوة حتمية ومكررة تعطي نفس النتيجة
- ✅ **لا كذب** — كل حقيقة لها `evidenceId` + `rawOutput` + `sha256`
- ✅ **لا تلاعب** — سجل التدقيق `hash-chained` لا يمكن تزويره

---

## 📦 هيكل المشروع المُحسّن

```
NetOps-Autopilot-REAL/
├── backend/                          # محرك الشبكات الحقيقي (Python FastAPI)
│   ├── app/main.py                   # API الرئيسي — evidence-first
│   ├── app/discovery/
│   │   ├── evidence.py               # نموذج الدليل — الحجر الأساس
│   │   ├── collectors/ssh_collector.py  # جمع حتمي SSH (قائمة بيضاء حسب البائع)
│   │   ├── collectors/snmp_collector.py
│   │   └── crawler.py                # زحف حتمي LLDP/CDP فقط
│   ├── app/topology/mapper.py        # خريطة فعلية/منطقية + كشف الحلقات
│   ├── app/intent/parser.py          # تحويل وصف الإنسان → intent منظم
│   ├── app/intent/designer.py        # تصميم حتمي — ثلاث قنوات أدلة للأدوار
│   ├── app/config/generator.py       # توليد تكوينات Cisco/Juniper/MikroTik/Fortinet/Aruba
│   ├── app/execution/engine.py       # محرك التنفيذ المرحلي: Backup→Dry-run→Diff→نافذ→Apply→Verify
│   ├── app/audit/log.py              # سجل تدقيق hash-chained
│   ├── app/chat/verifier.py          # مدقق الادعاءات — آخر بوابة قبل العرض
│   ├── app/chat/copilot.py           # المحاور الذكي المرتبط بالمحرك
│   └── app/api/                      # 7 وحدات API
├── agent/netops_agent.py             # الجسر الحقيقي — يعمل على الكمبيوتر الموصول
├── frontend/                         # واجهة React (محدثة للاتصال بـ /api/*)
├── docs/ARCHITECTURE.md              # وثائق معمارية عميقة
├── backups/                          # نسخ احتياطية قبل كل تطبيق
├── scripts/
└── NetOps-Autopilot-Complete/        # النسخة الأصلية المسحوبة (مرجع)
```

---

## 🔌 آلية العمل الأساسية — حقيقية فعلية

### 1. التركيب المادي (يقوم به الإنسان)
- ركّب الأجهزة الحقيقية (Cisco, Juniper, MikroTik, Fortinet, Aruba — مدعومة)
- صلها بالكابلات والواجهات المناسبة
- غذّها بالطاقة وشغّلها
- صل **جهازاً واحداً منها** بالكمبيوتر (عبر Ethernet/Console/USB)

### 2. الاكتشاف الحتمي (البرنامج)
```bash
python agent/netops_agent.py --seed-ip 10.0.0.1 --seed-id CORE-01 --username admin --password admin --intent campus
```
- يزحف عبر **جداول الجيران فقط** (LLDP/CDP) — لا يخمن وصلة غير معلنة
- لكل جهاز: يجمع `show version`, `show lldp neighbors detail`, `show interfaces`, `show running-config` ... عبر SSH
- كل جمع يسجل `rawOutput` غير معدل + `evidenceId` + `sha256`
- أي جهاز لا يرد = **فشل صريح** مستثنى من كل الاستنتاجات

### 3. الخريطة
- `topology/mapper.py` يبني `nodes` + `edges` + `sites` — كل edge يحمل `evidenceId`
- يكشف الحلقات (loops) ويحذر — لا يصحح تلقائياً (أمان)

### 4. النية — سؤال واحد
- الواجهة تسأل: "ما نوع الشبكة التي تريدها؟"
- `intent/parser.py` يحلل النص → `preset` حتمي:
  - `small-office` (10/20/30)
  - `campus` (10/20/30/40/99 + OSPF)
  - `branch`
  - `data-center`
- إذا النص لا يطابق → يطلب اختيار صريح — **صفر تخمين**

### 5. التصميم والتنفيذ الفعلي
- `designer.py` يحدد أدوار الأجهزة بثلاث قنوات (الطراز/الطوبولوجيا/الاسم) + يعلن التعارض
- يخصص: المنافذ/الواجهات → VLANs → IPs (10.0.<vlan>.0/24 حتمي) → SVI/DHCP → Routing (static/OSPF) → NAT/Firewall → Hardening
- `config/generator.py` يولد التكوينات **سطراً بسطر لكل بائع** — كل كتلة مربوطة بـ `Requirement IDs`
- `execution/engine.py` ينفذ **مرحلياً**:
  1. **Backup** — يقرأ `show running-config` ويحفظه في `backups/`
  2. **Dry-run** — يتحقق من الأوامر المدمرة
  3. **Diff** — يعرض الفروقات
  4. **Approve — نافذ** — لا أمر تعديل قبل كتابة `نافذ` حرفياً
  5. **Apply** — يرسل الكتل بالترتيب، أي `"% Invalid"` يوقف الجهاز
  6. **Verify** — يقرأ الحالة الفعلية بعد التنفيذ ويقارن بالمتطلبات → `PASS/FAIL`
  7. **Rollback** جاهز — `restore_<hostname>.py`

### 6. المحادثة الذكية
- `chat/copilot.py` مرتبط مباشرة بالمحرك — يفهم اللغة الطبيعية، يحلل النية، ينفذ فقط عبر القائمة البيضاء
- `chat/verifier.py` يفحص **كل جملة** قبل عرضها: `VERIFIED` / `UNVERIFIED` / `REJECTED`

---

## 🛠️ التقنيات — مستوى 30 عام خبرة

- **SSH**: Paramiko + Netmiko (Cisco IOS/XE, Juniper Junos, MikroTik RouterOS, Fortinet FortiOS, Aruba CX)
- **SNMP**: pysnmp للكشف الأولي
- **Parsers**: TextFSM + TTP — حتمية، لا LLM
- **Backend**: FastAPI + Pydantic + SQLAlchemy
- **Frontend**: Vite + React + React Router + Tailwind + Recharts + Radix — مطابقة للأصل
- **Evidence**: SHA256 + timestamp + durationMs + exitStatus
- **Audit**: Hash chain (SHA256(prevHash+seq+...))
- **Templates**: Jinja2 لكل بائع

---

## 🚀 التشغيل

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# API على http://localhost:8000/api
# Docs على http://localhost:8000/docs
```

### Agent (الجسر الحقيقي)
```bash
# 1. اكتشاف وتصميم فقط
python agent/netops_agent.py --seed-ip 192.168.1.1 --intent "campus OSPF hardened" --dry-run

# 2. تنفيذ كامل مع التحقق
python agent/netops_agent.py --seed-ip 192.168.1.1 --intent campus

# مع vault لكلمات المرور المخصصة
echo '{"BR3-SW-ACC-02": "MyPass123"}' > vault.json
python agent/netops_agent.py --seed-ip 192.168.1.1 --vault vault.json --intent small-office
```

### Frontend (الواجهة)
```bash
cd frontend
npm install
npm run dev  # http://localhost:5173 — تتصل بـ backend على 8000
```

### الواجهة الأصلية المسحوبة (للمقارنة)
```bash
cd ../NetOps-Autopilot-Complete
python -m http.server 8080  # نفس النسخة الأصلية 1:1
```

---

## 📊 الشبكات المدعومة

| الحجم | الأجهزة | الوصف |
|-------|---------|--------|
| صغيرة | 2-10 | مكتب صغير — static routing |
| متوسطة | 10-30 | فروع — static/OSPF |
| كبيرة | 30-100+ | Campus / Data Center — OSPF + Hardening |

كل الأحجام تستخدم **نفس المحرك** — الفرق فقط في `preset` ودرجة الزحف.

---

## 🔒 الأمان

- قائمة بيضاء صارمة لكل بائع — أي أمر خارجها `REJECTED before execution`
- الشات لا ينفذ تعديلاً مباشرة — التعديل فقط عبر `Change` workflow
- كل تنفيذ يسجل في `audit/log` مع `hash` لا يمكن تزويره
- النسخ الاحتياطية تُحفظ قبل أي تعديل

---

## 📖 الوثائق

- `docs/ARCHITECTURE.md` — معمارية عميقة (Phase 0 → REAL)
- `backend/app/*` — كود معلق بالعربية والإنجليزية
- `NetOps-Autopilot-Complete/README.md` — وصف النسخة الأصلية

---

## ✅ ما الذي يجعله حقيقياً وليس محاكاة؟

| الميزة | الواجهة الأصلية (Lab) | النسخة REAL |
|--------|------------------------|-------------|
| مصدر البيانات | `G.devices` مولدة في JS | أجهزة حقيقية عبر SSH |
| الزحف | محاكاة حتمية | `DeterministicCrawler` + Paramiko |
| التكوين | `Ja` سجلات وهمية | `Netmiko.send_config_set` فعلي |
| التحقق | قراءة وهمية | قراءة فعلية + مقارنة |
| السجل | محاكاة hash | `audit/log.py` حقيقي |

**المنطق واحد سطراً بسطر** — نفس الترتيب، نفس البوابات، نفس الـ evidence.

---

تم التطوير بأقصى درجات الدقة الهندسية — جاهز للعمل على الأجهزة الحقيقية اليوم.
