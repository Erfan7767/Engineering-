#!/bin/bash
set -e
echo "========================================"
echo " NetOps Autopilot V6 — مثبت macOS"
echo "========================================"

if ! command -v python3 &> /dev/null; then
  echo "[خطأ] python3 غير مثبت — ثبّت عبر brew install python"
  exit 1
fi

echo "[1/4] إنشاء بيئة..."
python3 -m venv venv
source venv/bin/activate

echo "[2/4] تثبيت المتطلبات..."
pip install -q -r src/backend/requirements.txt
pip install -q requests

echo "[3/4] واجهة..."
if command -v npm &> /dev/null; then
  (cd electron && npm install --silent)
else
  echo "[تخطي] npm غير موجود — سيعمل Python GUI"
fi

echo "[4/4] اختصار..."
mkdir -p ~/Desktop
cat > ~/Desktop/NetOps\ Autopilot.command << 'EOS'
#!/bin/bash
cd "$(dirname "$0")/NetOps-Autopilot-PC-Installer"
source venv/bin/activate
python python-gui/main.py
EOS
chmod +x ~/Desktop/NetOps\ Autopilot.command

echo "✅ تم — شغّل ~/Desktop/NetOps Autopilot.command أو python python-gui/main.py"
