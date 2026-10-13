#!/usr/bin/env bash
# ============================================================
#  LabTrace LogLens - start the local SIEM log monitor
#  Runs on http://127.0.0.1:5000 (set LOGLENS_ALLOW_LAN=1 for LAN)
# ============================================================
cd "$(dirname "$0")" || exit 1

if [ ! -f "venv/bin/python" ]; then
  echo "[ERROR] venv not found. Run:  python3 -m venv venv"
  echo "        then:  venv/bin/pip install -r requirements.txt"
  exit 1
fi

source venv/bin/activate
exec python run.py
