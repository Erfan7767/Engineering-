@echo off
chcp 65001 >nul
echo ========================================
echo  NetOps Autopilot V6 — مثبت الكمبيوتر
echo  دقة مجهرية 100%% — Evidence-First
echo ========================================
echo.

REM تحقق من Python
python --version >nul 2>&1
if errorlevel 1 (
  echo [خطأ] Python غير مثبت — حمّل Python 3.10+ من https://python.org
  pause
  exit /b 1
)

echo [1/4] إنشاء بيئة...
python -m venv venv
call venv\Scripts\activate.bat

echo [2/4] تثبيت المتطلبات...
pip install -q -r src\backend\requirements.txt
pip install -q requests

echo [3/4] تثبيت الواجهة (اختياري — Electron)...
where npm >nul 2>&1
if not errorlevel 1 (
  cd electron
  call npm install --silent
  cd ..
  echo [Electron] تم — شغّل npm start داخل electron
) else (
  echo [تخطي] npm غير موجود — سيعمل GUI بـ Python/Tkinter
)

echo [4/4] إنشاء اختصار سطح المكتب...
set SCRIPT=%~dp0python-gui\main.py
set SHORTCUT=%USERPROFILE%\Desktop\NetOps Autopilot.lnk
powershell -Command "$WshShell=New-Object -ComObject WScript.Shell; $Shortcut=$WshShell.CreateShortcut('%SHORTCUT%'); $Shortcut.TargetPath='%~dp0venv\Scripts\pythonw.exe'; $Shortcut.Arguments='\"%SCRIPT%\"'; $Shortcut.WorkingDirectory='%~dp0'; $Shortcut.IconLocation='%~dp0electron\icon.png'; $Shortcut.Save()"

echo.
echo ✅ تم التثبيت بنجاح!
echo ----------------------------------------
echo للتشغيل:
echo  1) GUI الكمبيوتر:  venv\Scripts\python python-gui\main.py
echo  2) أو:  install.bat سيُنشئ اختصار على سطح المكتب
echo  3) Electron: cd electron ^&^& npm start
echo  4) Backend API:  venv\Scripts\python -m uvicorn src.backend.app.main:app --host 127.0.0.1 --port 8000
echo ----------------------------------------
pause
