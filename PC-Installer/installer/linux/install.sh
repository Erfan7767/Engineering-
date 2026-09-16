#!/bin/bash
set -e
echo "========================================"
echo " NetOps Autopilot V6 — مثبت Linux"
echo "========================================"

if ! command -v python3 &> /dev/null; then
  echo "[خطأ] python3 غير مثبت"
  exit 1
fi

echo "[1/4] venv..."
python3 -m venv venv
source venv/bin/activate

echo "[2/4] pip..."
pip install -q -r src/backend/requirements.txt

echo "[3/4] electron..."
if command -v npm &> /dev/null; then (cd electron && npm install --silent); fi

echo "[4/4] اختصار..."
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/netops-autopilot.desktop << EOS
[Desktop Entry]
Name=NetOps Autopilot V6
Comment=مهندس شبكات آلي حقيقي — دقة مجهرية
Exec=$(pwd)/venv/bin/python $(pwd)/python-gui/main.py
Icon=$(pwd)/electron/icon.png
Terminal=false
Type=Application
Categories=Network;
EOS

echo "✅ تم — شغّل python python-gui/main.py أو من قائمة التطبيقات"
