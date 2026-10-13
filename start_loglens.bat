@echo off
REM ============================================================
REM  LabTrace LogLens - start the local SIEM log monitor
REM  Runs on http://127.0.0.1:5000 (set LOGLENS_ALLOW_LAN=1 for LAN)
REM ============================================================
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
  echo [ERROR] venv not found. Run:  python -m venv venv
  echo         then:  venv\Scripts\pip install -r requirements.txt
  pause
  exit /b 1
)

call venv\Scripts\activate.bat
python run.py
