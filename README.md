# LabTrace · LogLens — Local SIEM-Style Log Monitor

**CYBERHACK — BUILD. BREAK. DEFEND.**

Evidence-first access alerts for shared lab PCs — now with **automatic
real-time log collection**, **live detection** and a **SOC-style Live
Monitor** dashboard. *Explain every alert. Blame no one. Block nothing.*

Everything runs **locally on your laptop**. No cloud. No external services.

---

## Features

| Feature | Description |
|---------|-------------|
| **Secure Login** | bcrypt password hashing + Flask sessions |
| **Account Creation** | Self-registration for analysts |
| **Forgot Password** | Local reset-token flow (demo mode shows token) |
| **2FA (TOTP)** | Google Authenticator / Authy compatible |
| **Live Log Collection** | Windows Security log (4624/4625), Unix auth.log / journalctl, watched folder `data/incoming/`, UDP syslog on port 5140 |
| **Auto Detection** | Every 30 s: R1 Failure-Burst → Success · R2 After-Hours (APScheduler) |
| **Live Monitor** | `/monitor` dark SOC dashboard, auto-refresh 5 s, Chart.js bundled locally (offline) |
| **Server Status** | CPU / memory / disk of this laptop (psutil), ACTIVE badge |
| **Live Alert Banner** | New PRIORITY cases banner on the dashboard |
| **Human-in-the-loop** | Confirm / Dismiss only — never auto-block |
| **Audit Log** | Full action history |
| **Retention** | Raw logs older than 30 days auto-deleted (configurable) |
| **Auto-start with laptop** | Windows Task Scheduler / Linux systemd user service |

---

## Quick Start (Windows)

```bat
cd LabTrace_LogLens

:: one-time setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

:: run
venv\Scripts\python run.py
:: or simply:
start_loglens.bat
```

Open **http://127.0.0.1:5000**

### Demo Login

| Username | Password        | Role    |
|----------|-----------------|---------|
| admin    | LabTrace@2025   | admin   |
| analyst  | Analyst@2025    | analyst |

### Linux / Mac

```bash
cd LabTrace_LogLens
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py            # or: ./start_loglens.sh
```

---

## Testing the Live Pipeline (Windows)

Open **two** terminals (venv activated in both):

```bat
:: 1) start the app
python run.py

:: 2) generate fake login traffic into data\incoming\
python tools\generate_test_logs.py --interval 3

:: 3) simulate an attack burst (5 failures → success, triggers R1)
python tools\generate_test_logs.py --mode attack --interval 2

:: 4) simulate after-hours logins (triggers R2)
python tools\generate_test_logs.py --mode attack --after-hours

:: 5) send a syslog packet from another machine (or locally)
python tools\generate_test_logs.py --udp --mode mixed
```

Then:

1. Log in at **http://127.0.0.1:5000** → open **Live Monitor**.
2. Watch *Total Logs*, *Events/sec* and the collectors table update.
3. After ~30 s the detection scheduler creates cases; R1/R2 hits show up
   in **Latest Alerts** and on the dashboard (alert banner).
4. Click an alert → it opens the existing case view → **Confirm** or
   **Dismiss** (human-in-the-loop, never auto-block).

### Syslog from any machine

Point any syslog sender at this laptop on UDP port **5140**, e.g.:

```bash
logger -n 127.0.0.1 -P 5140 "Failed password for invalid user bob from 10.0.0.5 port 22 ssh2"
```

or from Python:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"<132>Mar 10 09:00:00 lab-pc sshd[1]: Failed password for invalid user bob from 10.0.0.5 port 22 ssh2",
         ("<laptop-ip>", 5140))
```

---

## Log Collection Details

| Source | How | Notes |
|--------|-----|-------|
| **Windows** | `pywin32` (primary) or `wevtutil` (fallback) | Security log, Event IDs 4624 (success logon) / 4625 (failed logon). Runs only on Windows. |
| **Linux / Mac** | tails `/var/log/auth.log` (or `/var/log/secure`, `/var/log/system.log`); falls back to `journalctl --output=short-iso` | Works without root if the log file is readable. |
| **Watched folder** | polls `data/incoming/` every 10 s | Drop any `.csv` or `.log` file — it is parsed and ingested automatically. Offsets are remembered, so a restart never re-reads old lines. |
| **Syslog UDP** | receiver on port **5140** | RFC3164 / RFC5424 / plain text. Failure vs Success is classified from the message. |

**Deduplication**: every record is hashed (SHA-256 over source, host,
account, computer, event, message, timestamp) — duplicates are silently
ignored, even across restarts.

**Normalized record** → `raw_logs` table:

```sql
CREATE TABLE raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,      -- 'YYYY-MM-DD HH:MM:SS' (local time)
    source TEXT NOT NULL,         -- windows | auth_log | file | syslog_udp
    host TEXT,
    account TEXT,
    computer TEXT,
    event TEXT,                   -- Failure | Success | Info
    message TEXT,
    severity TEXT,
    line_hash TEXT UNIQUE         -- sha256 dedup key
);
-- indexes on raw_logs(timestamp, source) and raw_logs(line_hash)
```

### CSV format for the watched folder

```csv
event_id,timestamp,account,computer,event,department_case
1,2025-03-10 09:05:12,a.raj,PC-02,Failure,CSE
```

`event` must be `Failure` or `Success` (anything else becomes `Info`).
Timestamp format: `YYYY-MM-DD HH:MM:SS`.
`.log` files are parsed as auth.log/journalctl-style lines, pipe-separated
lines, or stored as generic info records.

---

## Detection Rules

1. **R1 – Failure Burst → Success**
   ≥ N failed logins within W minutes, followed by a successful login.

2. **R2 – After-Hours Success**
   Successful login outside configured lab open–close hours.

**Priority mapping**
- **PRIORITY** = both R1 and R2 matched
- **REVIEW**   = only one rule matched
- **ROUTINE**  = neither (reason always shown)

Every 30 s the scheduler pulls new `raw_logs` rows, merges them with the
manually uploaded events and runs `detect_cases()` with your N, W and
lab-hours settings. Cases are upserted by `case_key`; **confirmed /
dismissed cases keep their human decision**. New or escalated PRIORITY /
REVIEW cases raise the live alert banner (acknowledge with one click).

Department column is **display-only** and is never used in detection.

---

## Live Monitor (`/monitor`)

Auto-refreshes every 5 s via JSON APIs (no CDN — Chart.js is bundled in
`static/js/chart.umd.min.js`, works fully offline):

- **Total Logs** — bar chart by source + total count
- **Last Logs** — events per 5 minutes (last 2 h)
- **Log Sources** — logs per source over time (last 6 h)
- **Collectors** — status of each collector with last-seen time
- **Server Status** — CPU %, memory %, disk % (psutil) with ACTIVE badge
- **Syslog** — donut chart with EPS, max EPS, average EPS
- **Total Logs timeline** — area chart, last 24 h
- **Latest Alerts** — table linking to the existing case view

---

## Auto-Start with Your Laptop

### Windows — Task Scheduler (At log on)

```bat
:: run once as your user — creates the task
schtasks /create /tn "LabTrace LogLens" /tr "\"%CD%\start_loglens.bat\"" /sc onlogon /rl highest
```

Or GUI: *Task Scheduler → Create Task → Triggers → "At log on" →
Actions → Start a program → `start_loglens.bat`*.

### Linux — systemd user service

```bash
mkdir -p ~/.config/systemd/user
cp deploy/loglens.service ~/.config/systemd/user/
# edit the WorkingDirectory/ExecStart paths in the copied file
systemctl --user daemon-reload
systemctl --user enable --now loglens.service
loginctl enable-linger $USER      # keep it running after logout
```

Check status: `systemctl --user status loglens.service`

---

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOGLENS_HOST` | `127.0.0.1` | Bind address (`0.0.0.0` for LAN) |
| `LOGLENS_ALLOW_LAN` | `0` | `1` → bind `0.0.0.0` |
| `LOGLENS_PORT` | `5000` | HTTP port |
| `LOGLENS_SYSLOG_PORT` | `5140` | UDP syslog receiver port |
| `LOGLENS_RETENTION_DAYS` | `30` | Auto-delete raw logs older than N days |
| `LOGLENS_DEBUG` | `0` | `1` → Flask debug mode (dev only) |
| `SECRET_KEY` | random | Flask session key (set explicitly for stable sessions) |

The app binds to **127.0.0.1 by default** and serves with **waitress**
(no debug reloader). The collector threads and the 30 s detection
scheduler start automatically with `run.py`.

---

## 2FA Setup

1. Login → click **Enable 2FA** in the top bar.
2. Scan the QR code with Google Authenticator / Authy / Microsoft Authenticator.
3. Enter the 6-digit code to activate.
4. On next login you will be prompted for the TOTP code.

---

## Project Structure

```
LabTrace_LogLens/
├── app/
│   ├── __init__.py
│   ├── config.py         # env-based configuration (host, ports, retention)
│   ├── main.py           # Flask routes, auth, 2FA, monitor APIs
│   ├── engine.py         # R1 / R2 detection engine (unchanged rules)
│   ├── collector.py      # background log collectors (Windows/Unix/file/UDP)
│   └── scheduler.py      # 30 s APScheduler detection job + retention
├── data/
│   ├── sample_lab_logs.csv
│   ├── incoming/         # watched folder — drop .csv / .log files here
│   └── labtrace.db       # created on first run (SQLite)
├── static/
│   ├── css/app.css
│   └── js/
│       ├── chart.umd.min.js  # Chart.js 4.4.3 — bundled, offline
│       ├── dashboard.js
│       └── monitor.js
├── templates/
│   ├── login.html / register.html / forgot.html / reset.html
│   ├── verify_2fa.html / setup_2fa.html
│   ├── dashboard.html
│   └── monitor.html
├── tools/
│   └── generate_test_logs.py   # fake login traffic for testing
├── deploy/
│   └── loglens.service         # systemd user service (Linux)
├── start_loglens.bat           # Windows launcher
├── start_loglens.sh            # Linux/Mac launcher
├── requirements.txt
├── run.py
└── README.md
```

---

## Security Notes

- Passwords hashed with **bcrypt**
- Session cookies: HttpOnly + SameSite=Lax
- Parameterized SQL (no injection)
- Upload size limited to 2 MB
- 2FA secrets stored in DB; verification uses time-window tolerance
- Collector dedup via SHA-256 hash per record; offsets persisted in SQLite
- Detection is **human-in-the-loop**: Confirm / Dismiss only, never auto-block
- Everything runs **locally** — no external services

---

## Tech Stack

- Python 3.10+
- Flask 3 · waitress (production server)
- SQLite (with indexes on `raw_logs(timestamp, source)`)
- APScheduler (30 s detection cadence)
- psutil (server status) · watchdog (optional; polling used by default)
- pywin32 (Windows event log, Windows only)
- Chart.js 4.4.3 (bundled locally, no CDN)
- Vanilla HTML / CSS / JS (dark cyber theme)

---

Built for **CYBERHACK** hackathon — LabTrace / LogLens.
