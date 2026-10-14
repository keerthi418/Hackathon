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
| **Auto Detection** | Every 30 s: R1 Failure-Burst→Success · R2 After-Hours · R3 Burst-No-Success · R4 Cross-PC · R5 Account-Switch · R6 Repeated-Risk (APScheduler) |
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

## Automated test suite

The project ships with a `unittest` suite (standard library only —
no new dependencies) covering all six rules and the existing
functionality:

```bat
:: run every test (from the project folder, venv activated)
python -m unittest discover -s tests -t .

:: verbose
python -m unittest discover -s tests -t . -v

:: engine rules only
python -m unittest tests.test_engine -v

:: app / API / scheduler only
python -m unittest tests.test_app -v
```

Scenarios covered:

- **R1** qualifying failures followed by success (and below-threshold /
  spread-out negative cases)
- **R2** successful login outside configured lab hours (incl. boundary)
- **R3** qualifying failures without a subsequent success, plus
  no-duplicate-alerts for overlapping windows
- **R4** failed attempts for one account across multiple computers
- **R5** rapid successful logins by multiple accounts on one computer
  (configurable threshold)
- **R6** repeated R1/R2 incidents within 24 h, including the
  duplicate-scheduler-run and outside-24 h negative cases
- normal logins trigger no unsupported alerts
- missing fields and malformed timestamps never crash detection
- repeated scheduler runs do **not** duplicate the same case
- existing R1/R2 results remain compatible
- authentication, dashboard, CSV import, case review (confirm /
  dismiss / escalate), audit log and all monitor APIs still work

Tests run against a **temporary** SQLite database, so the real
`data/labtrace.db` is never touched.

## Two-minute demo script

Prereqs: `venv\Scripts\activate` (or `source venv/bin/activate`),
then `python run.py`. Open **http://127.0.0.1:5000** and log in as
`admin / LabTrace@2025`.

| Time | Step | What you show |
|------|------|---------------|
| 0:00 | Open **Dashboard** | Compact top row: Open Cases, High Priority, Pending Reviews, Recent Events. Empty state before data loads. |
| 0:20 | Click **Load Demo CSV** | 30 sample events load. `x.user @ PC-01` appears as **PRIORITY** (R1+R2: 4 failures → success at 02:18, after hours). `guest_lab @ PC-PRG-07` is **REVIEW** (R1). |
| 0:40 | Click the **R1** filter chip | Only R1 cases remain; the table, severity badge, rule tag and score are visible. Click **All** to clear. |
| 1:00 | Click the `x.user @ PC-01` row | **Evidence Panel** opens: R1 and R2 explanation cards, each with severity, the event-derived explanation, threshold (N=3 / outside 08:30–17:30), window (W=5 min), matched event IDs `#22–#26`, and the recommended next step. Expand **Event history** and **Technical metadata** (collapsible). |
| 1:30 | Click **Confirm**, then **Dismiss** | Case status updates; the action is written to the **System Audit Log** (footer link). |
| 1:50 | Click **Escalate** on a REVIEW case | Case jumps to PRIORITY (High) and reopens — human-in-the-loop, nothing is blocked. |
| 2:00 | (optional) Open a second terminal and run `python tools\generate_test_logs.py --mode attack --interval 2` | Live collectors ingest the burst; within ~30 s the scheduler raises an R1/R2 alert and the red **alert banner** appears. |

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

**`cases` table** (extended, backward-compatible). Existing columns
(`case_key`, `account`, `computer`, `department`, `priority`, `r1`,
`r2`, `reason`, `human_check`, `event_count`, `matched_event_ids`,
`r1_detail`, `r2_detail`, `status`, `created_at`, `updated_at`,
`origin`, `is_new`) are unchanged. The following columns are **added**
via a safe `ALTER TABLE … ADD COLUMN` migration that works on existing
databases and never deletes data:

| Column | Type | Purpose |
|--------|------|---------|
| `r3`, `r4`, `r5`, `r6` | INTEGER | Rule fired (0/1) |
| `r3_detail` … `r6_detail` | TEXT (JSON) | Structured evidence per rule (counts, windows, timestamps, event IDs) |
| `rules` | TEXT | Comma-joined triggered rule IDs, e.g. `R1,R2` |
| `rule_details` | TEXT (JSON) | Full human-readable per-rule view (name, severity, explanation, recommendation, threshold, window, matched event IDs) |
| `severity` | TEXT | High / Medium / Low (derived from priority) |
| `score` | INTEGER | Rule-based prioritization score (0–100) |

**`rule_matches` table** (new) — stores one row per distinct rule
occurrence, deduplicated by a UNIQUE `fingerprint`. This is the
history R6 uses to detect recurrence without counting duplicate
scheduler runs:

```sql
CREATE TABLE rule_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_set TEXT,            -- e.g. 'R1' or 'R1,R2'
    account TEXT,
    computer TEXT,
    first_ts TEXT, last_ts TEXT,
    fingerprint TEXT UNIQUE,  -- sha256(account|computer|event ids)
    matched_event_ids TEXT,   -- JSON
    detail TEXT,              -- JSON (rule_details)
    case_key TEXT,
    origin TEXT DEFAULT 'live',
    created_at TEXT
);
```

**`settings` table** gains `r4_window` (10), `r5_threshold` (4),
`r5_window` (10), `r6_threshold` (2), `r6_hours` (24) — all with
defaults, added by the same safe migration.

**Migration behaviour.** `init_db()` runs on startup and is
idempotent: it only *adds* missing columns/tables and never
modifies or deletes existing users, logs, cases or audit records.
Cases written by an older engine (rule flags set but the new
`rules`/`rule_details` columns empty) are automatically refreshed
on the next detection pass so every alert is explainable.

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

All six rules run **locally** on every detection pass (every 30 s,
or on **Replay Detection**). Each rule is a small, deterministic,
independently testable function in `app/engine.py`. Detection never
blocks a user, terminates a session or isolates a host — it only
produces *explainable* cases for a human to review.

| Rule | Name | Default threshold | Fires when |
|------|------|-------------------|------------|
| **R1** | Failure Burst → Success | N=3 failures, W=5 min | ≥ N failures for one account+PC within W min, **followed by** a successful login |
| **R2** | After-Hours Success | lab hours 08:30–17:30 | A successful login outside the configured lab open/close times |
| **R3** | Failure Burst Without Success | N=3, W=5 min | ≥ N failures for one account+PC within W min with **no** successful login inside that window |
| **R4** | Cross-PC Failure Pattern | 10 min window | Failed logins for **one account** across **≥ 2 distinct lab PCs** within the window |
| **R5** | Rapid Account Switching | 4 accounts, 10 min | **≥ 4 distinct accounts** with successful logins on the **same PC** within the window |
| **R6** | Repeated Risk Pattern | 2 recurrences, 24 h | ≥ 2 distinct R1/R2 occurrences for the same account+PC within a rolling 24 h |

R4–R6 thresholds are configurable in **Detection Controls → R4–R6
thresholds** (dashboard) or via `PUT /api/settings`
(`r4_window`, `r5_threshold`, `r5_window`, `r6_threshold`,
`r6_hours`).

**Priority mapping** (case-level triage):
- **PRIORITY** = R1+R2 together, **or** R6 (a risk pattern recurred)
- **REVIEW**   = exactly one of R1 / R2 / R3 / R4 / R5
- **ROUTINE**  = no rule matched (reason always shown)

**Severity** is derived from priority: PRIORITY→High,
REVIEW→Medium, ROUTINE→Low. R5 is deliberately labelled
**Low** severity and carries an explicit false-positive warning
because shared labs naturally have many users.

**Rule-based prioritization score** (transparent, *not* a
probability of compromise):

```
score = min(100, sum of the weights of the triggered rules)
R1=40  R2=30  R3=25  R4=35  R5=15  R6=50
```

The score only helps order the review queue. It is computed from
rule matches, never from any ML/AI model, and is **not** a
likelihood of compromise.

**Deduplication.** Every rule occurrence is fingerprinted
(SHA-256 over account + computer + sorted matched event IDs) and
stored in `rule_matches`. A repeated scheduler run over unchanged
data produces the same fingerprint and is therefore **not**
counted as a new incident — this is what makes R6 ignore duplicate
scheduler runs. Clustering is greedy and non-overlapping, so
overlapping time windows never create duplicate R3/R4/R5 alerts.

Every 30 s the scheduler pulls new `raw_logs` rows, merges them
with the manually uploaded events and runs `detect_cases()` with
your N, W, lab-hours and R4–R6 settings. Cases are upserted by
`case_key`; **confirmed / dismissed cases keep their human
decision**. New or escalated PRIORITY / REVIEW cases raise the
live alert banner (acknowledge with one click).

Department column is **display-only** and is never used in
detection. A shared public IP address is **never** treated as
proof of a shared attacker — R4 groups strictly by
(account, computer, timestamp).

### Explainability

Every alert shows, per rule: rule ID + human-readable name,
severity, a transparent reason derived from the **actual matched
events**, the matched evidence + event IDs, the account and
computer, the detection threshold and time window, the recommended
next step, and the analyst review status. A rule is only shown as
triggered when it actually matched.

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
│   ├── main.py           # Flask routes, auth, 2FA, dashboard + monitor APIs
│   ├── engine.py         # R1–R6 detection engine (small, testable rules)
│   ├── collector.py      # background log collectors (Windows/Unix/file/UDP)
│   └── scheduler.py      # 30 s detection job, rule_matches store, retention
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
├── tests/
│   ├── test_engine.py   # unit tests for all six rules (R1–R6)
│   └── test_app.py      # auth, dashboard API, CSV import, review, scheduler dedup
├── tools/
│   ├── generate_test_logs.py   # fake login traffic for testing
│   ├── check_migration.py      # verifies safe migration on a DB copy
│   └── check_e2e.py            # HTTP end-to-end check (needs a running app)
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

## Limitations & known false-positive risks

- **R5 is a weak signal.** Shared labs legitimately have many
  users on one PC. It is labelled Low severity and carries an
  explicit warning; raise `r5_threshold` (default 4) or
  `r5_window` (default 10 min) if it is too noisy for your lab.
- **R3 vs R1 overlap at the edge.** If a success lands just
  after the failure window, R3 (no success *in* the window) and
  R1 (failures *before* a success) can both describe nearby
  events. This is intentional — they answer different questions —
  but an analyst should read the two explanations together.
- **R4 is not attribution.** It groups by (account, computer,
  timestamp) only. A shared public IP or NAT gateway is never
  treated as proof of a single attacker.
- **R6 depends on stored history.** It counts distinct
  R1/R2 occurrences recorded in `rule_matches`. After a database
  wipe the history restarts, and occurrences older than the
  retention period are pruned.
- **Timestamps are local time** (`YYYY-MM-DD HH:MM:SS`).
  Malformed or empty timestamps are skipped, never crash
  detection, and are never fabricated.
- **The audit log is a plain append-only SQLite table.** It
  records who did what and when, but it is **not** cryptographically
  tamper-proof — no hash chain or signature is implemented.
- **No automatic enforcement.** The system never blocks users,
  terminates sessions or isolates hosts; Confirm / Dismiss /
  Escalate are human-only.
- **Rule-based score, not a probability.** The 0–100 score is a
  deterministic sum of rule weights for triage ordering only.

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
