# NetOps Autopilot V6 TRANSCENDENCE — PC Installer

> مهندس شبكات آلي حقيقي — دقة مجهرية 100% — Evidence-First — 30 عام CCIE/JNCIE

هذا المستودع يحتوي على التحديثات الجديدة كاملة بدون نقص — مزامنة من https://netops-autopilot-m6r65hk.rork.app الأصلي.

## المحتويات
- `backend/` — محرك Python FastAPI — Evidence-First + Hash Chain + Twin + Heal
- `frontend/` — واجهة React + static-demo.html
- `agent/netops_agent.py` — الجسر الحقيقي
- `PC-Installer/` — برنامج الكمبيوتر القابل للتثبيت (Windows/macOS/Linux)
- `docs/` — ARCHITECTURE + CERTIFICATIONS + MICROPRECISION + PROOF_V4
- `original-mirror/` — الأصل المسحوب 1:1

## التثبيت على الكمبيوتر
```bat
# Windows
installer/windows/install.bat  # أو فك PC-Installer.zip → install.bat
# macOS/Linux
./installer/macos/install.sh
./installer/linux/install.sh
```

## التشغيل
```bash
python agent/netops_agent.py --seed-ip 10.0.0.1 --intent campus
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

المزامنة: 2026-09-14 — بدون نقص — بدون تخمين — بدون تغيير
