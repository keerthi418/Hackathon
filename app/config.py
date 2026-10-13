"""
LabTrace · LogLens — Central configuration

All values can be overridden with environment variables so the same code
runs on a laptop (default: local-only) or opened to the LAN on purpose.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── Storage ────────────────────────────────────────────────────────
DB_PATH = os.path.join(BASE_DIR, "data", "labtrace.db")
SAMPLE_CSV = os.path.join(BASE_DIR, "data", "sample_lab_logs.csv")
INCOMING_DIR = os.path.join(BASE_DIR, "data", "incoming")

# ─── Server ─────────────────────────────────────────────────────────
# Default: bind to loopback only. Set LOGLENS_ALLOW_LAN=1 (or
# LOGLENS_HOST=0.0.0.0) to expose the dashboard on the LAN.
ALLOW_LAN = os.environ.get("LOGLENS_ALLOW_LAN", "0") == "1"
HOST = os.environ.get("LOGLENS_HOST", "0.0.0.0" if ALLOW_LAN else "127.0.0.1")
PORT = int(os.environ.get("LOGLENS_PORT", "5000"))
DEBUG = os.environ.get("LOGLENS_DEBUG", "0") == "1"

# ─── Collectors ─────────────────────────────────────────────────────
SYSLOG_PORT = int(os.environ.get("LOGLENS_SYSLOG_PORT", "5140"))
COLLECTOR_POLL_SECONDS = 10          # file watcher / event log poll interval
SYSLOG_THREAD_TIMEOUT = 1.0          # UDP socket recv timeout (s)

# ─── Detection scheduler ────────────────────────────────────────────
DETECT_INTERVAL_SECONDS = 30         # APScheduler cadence

# ─── Retention ──────────────────────────────────────────────────────
RETENTION_DAYS = int(os.environ.get("LOGLENS_RETENTION_DAYS", "30"))

# ─── Misc ───────────────────────────────────────────────────────────
MAX_EPS_HISTORY_SECONDS = 3600       # ring buffer size for EPS stats
SERVER_SAMPLE_SECONDS = 2            # psutil sampling cadence
