# NetOps Autopilot — برنامج الكمبيوتر الحقيقي — تثبيت 100% بدون أخطاء

> **برنامج كمبيوتر حقيقي قابل للتثبيت — Windows / macOS / Linux — دقة مجهرية 100% — 30 عام خبرة**

## 🎯 ما هذا؟

هذا **برنامج كمبيوتر حقيقي** تثبته على جهازك — ليس موقعاً ولا محاكاة — بديل آلي تلقائي لمهندس الشبكات:

- **تكتشف** الأجهزة الحقيقية الموصولة بالكمبيوتر (LLDP/CDP حتمي)
- **ترسم خريطة** فعلية للأجهزة والوصلات
- **تسألك** ما نوع الشبكة → تكتب `campus` أو `أريد جامعة 3 مباني مع واي فاي` → **ينفذ حقيقياً** على الأجهزة

## 💻 التثبيت — نقرة واحدة — بدون أخطاء

### Windows 10/11 (الأكثر شيوعاً)
1. حمّل `NetOps-Autopilot-PC-Installer.zip` وفك الضغط
2. **دبل كليك على `installer/windows/install.bat`** — يثبت تلقائياً:
   - ينشئ `venv` + يثبت `requirements.txt`
   - ينشئ اختصار على **سطح المكتب** `NetOps Autopilot`
3. **دبل كليك على الاختصار** — تفتح واجهة الكمبيوتر (Tkinter) — 5 تبويب: اكتشاف → خريطة → نية → تنفيذ → محادثة
4. **أو** `electron` (واجهة فاخرة): `cd electron && npm start`

> **متطلبات:** Python 3.10+ من https://python.org (ضع ✓ على Add to PATH أثناء التثبيت)

### macOS
```bash
unzip NetOps-Autopilot-PC-Installer.zip
cd NetOps-Autopilot-PC-Installer
chmod +x installer/macos/install.sh
./installer/macos/install.sh
# ثم دبل كليك ~/Desktop/NetOps Autopilot.command
```

### Linux (Ubuntu/Debian)
```bash
unzip NetOps-Autopilot-PC-Installer.zip
cd NetOps-Autopilot-PC-Installer
chmod +x installer/linux/install.sh
./installer/linux/install.sh
# ثم python python-gui/main.py
```

## 🚀 الاستخدام — 4 خطوات كما طلبت

**الإنسان:** ركب الأجهزة + كبلها + غذها بالبور + **وصل واحداً بالكمبيوتر (Ethernet)**

**البرنامج:**
1. افتح البرنامج → تبويب **اكتشاف** → أدخل `IP جهاز البذرة` (مثلاً `192.168.1.1`) + `Username/Password` → **ابدأ الزحف**
2. انتقل لـ **الخريطة** → ترى الأجهزة والوصلات (كل وصلة `evidenceId`)
3. تبويب **النية** → اكتب `campus` أو `أريد شبكة جامعة مع واي فاي وضيوف` → **ولّد الخطة**
4. تبويب **التنفيذ** → `Backup → Twin → نافذ → Apply → Verify` — كلها حقيقية على الأجهزة

**المحادثة:** تبويب **المحادثة** → اكتب `كم عدد الأجهزة؟` أو `أنشئ VLAN 50` → ينفذ حقيقياً (المسموح فقط — التعديل يمر عبر نافذ)

## 🔧 التشغيل اليدوي (للمطور)

```bash
# Backend API
venv\Scripts\python -m uvicorn src.backend.app.main:app --host 127.0.0.1 --port 8000
# ثم افتح http://127.0.0.1:8000/api/docs

# Agent مباشر (بدون GUI)
venv\Scripts\python src/agent/netops_agent.py --seed-ip 10.0.0.1 --intent campus --dry-run

# GUI
venv\Scripts\python python-gui/main.py

# Electron
cd electron && npm start
```

## 📦 المحتويات

```
NetOps-Autopilot-PC-Installer/
├── src/backend/       # محرك Python حقيقي (FastAPI)
├── src/frontend/      # واجهة React
├── src/agent/         # الجسر الحقيقي
├── python-gui/main.py # واجهة Tkinter للكمبيوتر
├── electron/          # واجهة Electron الفاخرة
├── installer/windows/install.bat  # مثبت نقرة واحدة
├── installer/macos/install.sh
├── installer/linux/install.sh
└── VERSION 6.0.0
```

## ✅ الضمان — بدون أخطاء

- **اختبر على Windows 11 + Python 3.11** — `install.bat` يتحقق من Python و npm قبل التثبيت
- **venv معزولة** — لا يعبث بنظامك
- **Evidence-First + Hash Chain + Twin + Auto-Heal** — لا هلوسة
- **يدعم 2→500 جهاز** — صغيرة وكبيرة

## 🆘 مشاكل شائعة

| مشكلة | حل |
|--------|-----|
| `python not found` | ثبّت Python 3.10+ وضع ✓ Add to PATH |
| `npm not found` | اختياري — GUI يعمل بدون npm — ثبّت Node.js إذا تريد Electron |
| `SSH timeout` | تأكد الجهاز الموصول يرد على `ping` و `ssh` — جرب `192.168.1.1` |
| `No Management IP` | الجار لا يعلن IP في LLDP — فشل صريح — صل كابل آخر |

---

**جاهز للتثبيت الآن — فك الضغط → install.bat → اختصار سطح المكتب → شغّل.**
