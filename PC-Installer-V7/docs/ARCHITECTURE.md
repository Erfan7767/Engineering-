# NetOps Autopilot REAL — الوثائق المعمارية Phase 0 → REAL

> مهندس شبكات آلي حقيقي — Evidence-First — لا هلوسة — لا تخمين — لا تجاهل

## 1. المبدأ الحاكم

**كل حقيقة يجب أن تستند إلى دليل خام (rawOutput) تم جمعه فعلياً من الجهاز.**
- أي ادعاء بلا `evidenceId` = `UNVERIFIED` ويُعرض كفرضية مع تحذير
- أي ادعاء يذكر كياناً خارج المخزون = `REJECTED` ويُحذف قبل العرض
- أي فشل جمع = إعلان صريح `failures[]` مستثنى من كل الاستنتاجات — لا يُدمج مع الناجح

## 2. دورة الحياة الحتمية

```
[إنسان: ركب الأجهزة + كابلات + طاقة + وصل seed بالكمبيوتر]
        │
        ▼
[1] DISCOVER — زحف حتمي عبر LLDP/CDP فقط (DeterministicCrawler)
    • يبدأ من seedDevice
    • يقرأ جدول الجيران → يستخرج mgmtIp → يزحف للجار
    • لا يخمن وصلة غير معلنة
    • كل فشل = failure صريح
        │
        ▼
[2] MAP — Topo Mapper يبني الخريطة الفعلية/المنطقية
    • nodes + edges + sites + loops detection
    • كل edge يحمل evidenceId
        │
        ▼
[3] INTENT — سؤال واحد للإنسان: "ما نوع الشبكة التي تريدها؟"
    • parser يحول النص إلى preset حتمي (small-office/campus/branch/dc)
    • إذا النص لا يطابق — يطلب اختيار صريح — صفر تخمين
        │
        ▼
[4] DESIGN — Designer يولد خطة حتمية
    • تصنيف أدوار بثلاث قنوات (الطراز/الطوبولوجيا/الاسم) + كشف التعارض
    • تخصيص VLAN/ports/SVI/DHCP/Routing/Hardening
    • كل كتلة مربوطة بـ Requirement IDs
        │
        ▼
[5] GENERATE — Config Generator لكل بائع
    • Cisco / Juniper / MikroTik / Fortinet / Aruba — قوالب Jinja2 سطر بسطر
    • المخرجات: plan.json + <device>.cfg
        │
        ▼
[6] STAGED EXECUTION — نفس المحرك سطراً بسطر للمحاكاة والواقع
    Backup → Dry-run → Diff → Approve(نافذ) → Apply → Verify → Acceptance
    • أي Vendor error line يوقف الجهاز
    • Verify يقرأ الحالة الفعلية بعد التنفيذ ويقارن بالمتطلبات
        │
        ▼
[7] AUDIT — سجل متسلسل hash-chained
    seq + timestamp + actor + action + target + outcome + hash(prev)
        │
        ▼
[8] CHAT — Copilot مرتبط مباشرة بالمحرك
    • القائمة البيضاء: قراءة فقط مباشرة، تعديل فقط عبر مسار Change
    • claim_verifier يفحص كل جملة قبل العرض
```

## 3. الطبقات

### 3.1 Collectors (الجمع)
- `ssh_collector.py` — Paramiko/Netmiko، قائمة بيضاء صارمة `ALLOWLIST_COMMANDS` حسب البائع
- `snmp_collector.py` — للمعدات التي لا تسمح بـ SSH
- كل تنفيذ يسجل `EvidenceRecord{deviceId, command, rawOutput, evidenceId, sha256, durationMs, exitStatus}`

### 3.2 Parsers
- `cdp_parser`, `lldp_parser`, `version_parser`, `interface_parser`, `config_parser` — كلها TextFSM/TTP حتمية، لا LLM

### 3.3 Evidence Store
- `evidence.py` — مخزن الأدلة + `failures[]` — المصدر الوحيد للحقيقة

### 3.4 Crawler
- `crawler.py` — يزحف فقط عبر `Management Address` المذكور في LLDP/CDP — إذا لا يوجد IP → failure صريح

### 3.5 Designer
- `designer.py` — يحدد الأدوار، يوزع المنافذ، يبني blocks مع traceability

### 3.6 Execution Engine
- `engine.py` — 7 مراحل مرحلية — نفس الترتيب في المحاكاة والواقع

### 3.7 Audit
- `audit/log.py` — hash chain لا يمكن التلاعب به — verify_chain()

### 3.8 Chat
- `chat/copilot.py` + `chat/verifier.py` — كل إجابة تمر عبر verifier قبل العرض

## 4. الأمان والبوابات

- **نافذ (Gate)**: لا أمر تعديل قبل كتابة `نافذ` حرفياً — نفس السلوك في الحدود الفعلية
- **قائمة بيضاء**: الشات لا ينفذ إلا أوامر قراءة؛ التعديل فقط عبر `Change` workflow (Plan→Dry-run→Diff→Approve→Apply→Verify)
- **Backup أولاً**: قبل أي تعديل، نسخة كاملة في `backups/<device>_<timestamp>.cfg`
- **Rollback جاهز**: `restore_<hostname>.py` + `restore_all.ps1` مولدة تلقائياً

## 5. التعامل مع الفشل

| الحالة | السلوك |
|--------|--------|
| جهاز لا يرد | `failures[]` + مستثنى من كل الاستنتاجات + يظهر في "فشل الجمع" |
| جار بلا mgmt IP | failure صريح "cannot crawl — declared" |
| أمر غير في القائمة البيضاء | `REJECTED before execution` + audit blocked |
| Vendor error line | يوقف الجهاز، يعلن `failed`، يسلح التراجع |
| نص intent غير معروف | `ok:false` + يطلب اختيار صريح — لا يخمن |

## 6. المقاييس

- يدعم 5 بائعين، 4 presets، OSPF/static، hardened/standard
- يزحف حتى 20 hop (قابل للزيادة)
- يولد configs لـ 58 جهاز في <2 ثانية (lab) — وفي الواقع يعتمد على زمن SSH
- كل evidenceId فريد ومستشهد به في الواجهة بزر "الدليل"

## 7. الفرق بين المحاكاة والواقع

|  | Lab (الحالي في الواجهة) | Real (Agent) |
|---|---|---|
| مصدر البيانات | `G.devices` مولدة من كود JS داخل `index-BBAnUz2e.js` | أجهزة حقيقية عبر SSH |
| الزحف | محاكاة حتمية مطابقة للمنطق | Paramiko فعلي |
| التطبيق | سجلات `Ja` محاكاة | Netmiko send_config_set فعلي |
| التحقق | قراءة rawOutput محاكاة | SSH قراءة فعلية |
| السلسلة | نفس المحرك سطراً بسطر — لا فرق منطقي |

النظام الحالي في الواجهة هو **محاكاة حتمية مطابقة للمحرك سطراً بسطر** — لنقله للواقع شغّل `agent/netops_agent.py` على الكمبيوتر الموصول.

## 8. خريطة الملفات

```
backend/app/
  discovery/evidence.py, collectors/ssh_collector.py, crawler.py
  topology/mapper.py
  intent/parser.py, designer.py
  config/generator.py + templates/
  execution/engine.py
  audit/log.py
  chat/verifier.py, copilot.py
  api/ (discovery, plan, execution, topology, chat, audit, health)
agent/netops_agent.py
frontend/src/ (Wiring to /api/*)
```

## 9. التحقق

- `audit/verify` — يتحقق من سلامة hash chain
- `evidence` — كل rawOutput قابل للعرض عبر زر "الدليل"
- `verification.json` — حكم قبول PASS/FAIL/PARTIAL بعدد الفحوص المجتازة

---

**الخلاصة**: النظام ليس واجهة شكلية — هو محرك حتمي evidence-first يمكن تشغيله على أجهزة حقيقية اليوم عبر `agent/netops_agent.py --seed-ip 10.0.0.1 --intent campus`، وكل مرحلة قابلة للتتبع والتحقق.
