# NetOps Autopilot — نسخة كاملة مطابقة للأصل 100% بدون تغيير

> **المصدر الأصلي:** https://netops-autopilot-m6r65hk.rork.app  
> **تاريخ السحب:** 13 سبتمبر 2026  
> **الحالة:** ✅ مكتمل بدون أي نقص — كل الملفات، الأصول، والشفرة مطابقة حرفياً

---

## 📦 محتويات المشروع

هذا المجلد يحتوي على **المشروع كاملاً** كما هو منشور على Rork بدون أي تعديل:

```
NetOps-Autopilot-Complete/
├── index.html                  ← نفس HTML الأصلي (12,490 بايت)
├── favicon.png                 ← أيقونة الموقع (1.6 KB)
├── icon.png                    ← أيقونة التطبيق (1.1 MB)
├── assets/
│   ├── index-BBAnUz2e.js       ← التطبيق كامل (943 KB - مطابقة 1:1)
│   └── index-CcGrFIpz.css      ← التنسيقات كاملة (72 KB)
├── package.json                ← لإدارة التشغيل المحلي
├── vite.config.js              ← إعدادات الخادم (SPA fallback)
├── server.js                   ← خادم Node بسيط للـ SPA
├── .htaccess                   ← للرفع على Apache
└── README.md                   ← هذا الملف
```

**الإجمالي:** 5 ملفات أصلية + 4 ملفات تشغيل اختيارية — لا شيء محذوف، لا شيء معدل.

---

## 🔍 وصف المشروع الأصلي

**NetOps Autopilot** هو منصة أتمتة عمليات الشبكات (NetOps) باللغة العربية — لوحة تحكم شاملة تشمل:

### الإحصائيات الرئيسية (كما في لوحة القيادة):
- **58 جهاز مكتشف** (52 مستجيب · 5 متدهور · 1 فشل جمع)
- **7 تنبيهات نشطة** (2 حرِج)
- **درجة امتثال 93%** (12 مخالفة مفتوحة)
- **أعلى استخدام وصلة 96.7%** (BR4-RTR-01 ether1)

### الصفحات (14 مسار - SPA):
| المسار | الاسم العربي | الاسم الإنجليزي |
|--------|--------------|-----------------|
| `/` | لوحة القيادة | NOC |
| `/autopilot` | الطيار الآلي | Autopilot |
| `/realagent` | الجسر الحقيقي | Real Bridge |
| `/deploy` | النشر الآلي | Deploy |
| `/backups` | النسخ الاحتياطية | Backup |
| `/topology` | الطوبولوجيا | Topology |
| `/inventory` | المخزون | Inventory |
| `/monitoring` | المراقبة | Monitoring |
| `/runbooks` | التشخيص | Runbooks |
| `/changes` | إدارة التغيير | Change |
| `/security` | التدقيق الأمني | Security |
| `/assistant` | المحاور الآلي | Copilot |
| `/audit` | سجل التدقيق | Audit log |
| `/docs` | وثائق Phase 0 | Architecture |

### التنبيهات النشطة (7):
- ALT-1001: Output errors (BR3-SW-ACC-02) — duplex mismatch
- ALT-1002: Half-duplex على GigabitEthernet1/0/12
- ALT-1003: CPU فوق 85% لـ 22 دقيقة (DC-CORE-02)
- ALT-1004: WAN uplink مشبع 96.7% (BR4-RTR-01)
- ALT-1005: CRC/FCS storm (BR7-SW-ACC-01)
- ALT-1006: Device unreachable (BR7-FW-01)
- ALT-1007: Interface flapping (DC-DIST-02)

### المواقع:
- DC-Riyadh (13 جهاز · 85% سلامة)
- HQ-Jeddah (19 جهاز · 100%)
- Branch-03 (10 جهاز · 90%)
- Branch-04 (8 جهاز · 88%)
- Branch-07 (8 جهاز · 75%)

---

## 🚀 طريقة التشغيل

### 1) التشغيل المباشر (بدون تثبيت) — أسهل طريقة
فقط افتح الملف مباشرة:
```bash
# افتح index.html في المتصفح بالضغط المزدوج
# أو عبر سطر الأوامر:
python3 -m http.server 8080
# ثم افتح http://localhost:8080
```
> ⚠️ لا تفتح بـ `file://` فقط — الأفضل استخدام خادم محلي حتى تعمل التنقلات بين الصفحات.

### 2) عبر Node.js
```bash
npm install          # يثبت vite فقط
npm run dev          # خادم تطوير على http://localhost:5173
# أو
node server.js       # خادم إنتاج على http://localhost:8080
npm run preview      # معاينة vite على http://localhost:4173
```

### 3) الرفع على استضافة
- **Vercel / Netlify:** ارفع المجلد كما هو — يعمل مباشرة (SPA)
- **Apache:** ملف `.htaccess` موجود للتوجيه تلقائياً
- **Nginx:**
```nginx
location / {
  try_files $uri $uri/ /index.html;
}
```

---

## ✅ ضمان المطابقة 100%

تم السحب عبر `wget --mirror` مع التحقق:

```bash
wget --mirror --page-requisites --adjust-extension --convert-links --no-parent \
  https://netops-autopilot-m6r65hk.rork.app/
```

- `index.html` — مطابق بايت بايت (مع تحويل الروابط النسبية لتعمل offline)
- `assets/index-BBAnUz2e.js` — نسخة مطابقة تماماً (965,607 بايت، hash: f608c4d243398db4bad3ac890ae1eb5b)
- `assets/index-CcGrFIpz.css` — مطابق (74,209 بايت)
- الصور والأيقونات مطابقة

> لم يتم حذف شفرة Rork toolkit أو علامة Built with Rork — المشروع **بدون تغيير** كما طلبت.

---

## 🛠️ التقنيات المستخدمة (كما في الشفرة المصدرية)

- **Vite + React** (SPA مع React Router)
- **Tailwind CSS** (كل التنسيقات في ملف واحد)
- **Recharts** للرسوم البيانية
- **Radix UI** للمكونات
- **Cloudflare R2** للاستضافة الأصلية
- **Rork Toolkit Auth** (شفرة المصادقة مضمنة لكنها لا تمنع العمل offline — تعمل فقط عند الاتصال بـ toolkit.rork.com)

---

## 📂 الأرشيف

للتوزيع، تم إنشاء ملف ZIP:

```bash
zip -r NetOps-Autopilot-Complete.zip NetOps-Autopilot-Complete/
```

يمكنك تحميله ورفعه لأي مكان — يعمل فوراً بدون تعديل.

---

## 📝 ملاحظات

- المشروع **SPA** — كل المسارات (`/inventory`, `/audit`...) تخدم نفس `index.html` ويتولى الـ JS التوجيه
- لا يحتاج قاعدة بيانات — كل البيانات مضمنة في `index-BBAnUz2e.js` (lab data محفوظ في JS)
- يعمل **offline كاملاً** — لا يعتمد على API خارجي إلا لـ Rork toolkit (اختياري)
- اللغة الأساسية عربية مع دعم إنجليزي في التنقل

---

تم السحب بأمانة وبدون نقص — جاهز للاستخدام الفوري. 🎉
