"""
LabTrace · LogLens — Background Log Collector

Collects login/security events from local sources into the SQLite
`raw_logs` table, completely offline:

  * Windows : Security event log (Event ID 4624 / 4625) via pywin32,
              with a `wevtutil` fallback.
  * Linux/Mac : /var/log/auth.log (or /var/log/secure, /var/log/system.log)
              tail, with a `journalctl` fallback.
  * Watched folder : data/incoming/ — every new .csv / .log file dropped
              there is parsed and ingested (10 s polling).
  * UDP syslog receiver : port 5140, so other machines can send logs.

Deduplication : every record is hashed (sha256 over the normalized
fields) and stored in raw_logs.line_hash (UNIQUE) — a restart never
re-ingests old records. The last read position (byte offset for files,
last event timestamp for the event log) is persisted in the
`collector_state` table.

Every record is normalized to the engine's format:
  event_id, timestamp, account, computer, event (Failure/Success/Info),
  department_case.
"""
import csv
import hashlib
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from app.config import (
    BASE_DIR,
    COLLECTOR_POLL_SECONDS,
    DB_PATH,
    INCOMING_DIR,
    MAX_EPS_HISTORY_SECONDS,
    SERVER_SAMPLE_SECONDS,
    SYSLOG_PORT,
    SYSLOG_THREAD_TIMEOUT,
)

HOSTNAME = socket.gethostname()

# ─── DB helpers (short-lived connections → thread safe) ───────────


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(INCOMING_DIR, exist_ok=True)
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS raw_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                host TEXT DEFAULT '',
                account TEXT DEFAULT '',
                computer TEXT DEFAULT '',
                event TEXT DEFAULT 'Info',
                message TEXT DEFAULT '',
                severity TEXT DEFAULT 'Informational',
                line_hash TEXT UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_raw_logs_ts
                ON raw_logs(timestamp, source);
            CREATE INDEX IF NOT EXISTS idx_raw_logs_hash
                ON raw_logs(line_hash);

            CREATE TABLE IF NOT EXISTS collector_state (
                source TEXT PRIMARY KEY,
                last_position INTEGER DEFAULT 0,
                last_seen TEXT,
                extra TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


# ─── State (last read positions, last-seen stamps) ──────────────


def get_state(source):
    """Return dict {last_position, last_seen, extra} for a collector source."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT last_position, last_seen, extra FROM collector_state WHERE source=?",
            (source,),
        ).fetchone()
        if not row:
            return {"last_position": 0, "last_seen": None, "extra": {}}
        extra = {}
        try:
            extra = json_loads(row["extra"]) if row["extra"] else {}
        except Exception:
            extra = {}
        return {
            "last_position": row["last_position"] or 0,
            "last_seen": row["last_seen"],
            "extra": extra,
        }
    finally:
        conn.close()


def set_state(source, last_position=None, last_seen=None, extra=None):
    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO collector_state (source, last_position, last_seen, extra)
               VALUES (?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET
                 last_position = COALESCE(excluded.last_position, collector_state.last_position),
                 last_seen = COALESCE(excluded.last_seen, collector_state.last_seen),
                 extra = COALESCE(excluded.extra, collector_state.extra)""",
            (
                source,
                last_position,
                last_seen,
                json_dumps(extra) if extra is not None else None,
            ),
        )
        conn.commit()
    except sqlite3.OperationalError:
        # table might not exist yet on very first run
        ensure_schema()
    finally:
        conn.close()


# tiny JSON wrappers so this module never imports flask
try:
    import json as _json

    def json_loads(s):
        return _json.loads(s)

    def json_dumps(o):
        return _json.dumps(o)

except Exception:  # pragma: no cover
    def json_loads(s):
        return {}

    def json_dumps(o):
        return "{}"


# ─── Normalization helpers ─────────────────────────────────────

EVENT_ID_RE = re.compile(r"[A-Za-z0-9]+")


def normalize_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


def parse_ts_flexible(s):
    """Parse many timestamp shapes → 'YYYY-MM-DD HH:MM:SS' (local) or None."""
    if not s:
        return None
    s = str(s).strip()
    # ISO with T / Z / offset
    iso = s.replace("T", " ")
    is_utc = iso.endswith("Z")
    iso = iso.rstrip("Z")
    # strip microseconds / timezone offsets
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?", iso)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        if is_utc:
            dt = dt.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None)
        return normalize_ts(dt)
    # wevtutil style "2025-03-10 09:05:12.000"
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", s)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None
    # syslog style "Mar 10 09:05:12" → infer year
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", s)
    if m:
        months = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
        }
        mon = months.get(m.group(1))
        if not mon:
            return None
        try:
            hh, mm, ss = map(int, m.group(3).split(":"))
        except ValueError:
            return None
        now = datetime.now()
        year = now.year
        try:
            dt = datetime(year, mon, int(m.group(2)), hh, mm, ss)
        except ValueError:
            return None
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=year - 1)
        return normalize_ts(dt)
    # "YYYY-MM-DD HH:MM" (minute precision)
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2})", s)
    if m:
        try:
            return datetime.strptime(m.group(1) + ":00", "%Y-%m-%d %H:%M:%S").strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None
    return None


def classify_message(msg):
    """(event, account) from a free-text log/syslog message."""
    m = (msg or "").lower()
    account = ""
    for pat in (
        r"failed (?:password|publickey) for invalid user (\S+)",
        r"failed (?:password|publickey) for (\S+)",
        r"accepted (?:password|publickey) for invalid user (\S+)",
        r"accepted (?:password|publickey) for (\S+)",
        r"for invalid user (\S+)",
        r"for user (\S+)",
        r"user[=:]\s*([A-Za-z0-9._@\-]+)",
        r"login(?:name)?[=: ]\s*([A-Za-z0-9._@\-]+)",
    ):
        mm = re.search(pat, m)
        if mm:
            account = mm.group(1).strip(".,;:\"'")
            break

    if re.search(
        r"failed (?:password|publickey)|authentication failure|invalid user|"
        r"failed to|denied|logon failure|error",
        m,
    ):
        event = "Failure"
    elif re.search(
        r"accepted (?:password|publickey)|logged in|login succeed|logon success|"
        r"successfully (?:logged|authenticated)",
        m,
    ):
        event = "Success"
    else:
        event = "Info"
    return event, account


AUTH_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
ISO_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)


def parse_syslog_line(line):
    """Parse one auth.log / journalctl line → normalized dict or None."""
    line = line.strip()
    if not line:
        return None
    m = ISO_LINE_RE.match(line) or AUTH_LINE_RE.match(line)
    if not m:
        return None
    ts = parse_ts_flexible(m.group("ts"))
    if not ts:
        return None
    event, account = classify_message(m.group("msg"))
    return {
        "timestamp": ts,
        "host": m.group("host"),
        "account": account,
        "computer": m.group("host"),
        "event": event,
        "message": m.group("msg"),
        "severity": "Error" if event == "Failure" else "Informational",
    }


def parse_pipe_line(line):
    """'timestamp|account|computer|event|message' style lines."""
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 5:
        return None
    ts = parse_ts_flexible(parts[0])
    if not ts:
        return None
    event = parts[3].strip().capitalize()
    if event not in ("Failure", "Success"):
        event = "Info"
    return {
        "timestamp": ts,
        "host": parts[2] if len(parts) > 4 else HOSTNAME,
        "account": parts[1],
        "computer": parts[2],
        "event": event,
        "message": parts[4],
        "severity": "Informational",
    }


# ─── Ingestion (hash dedup) ─────────────────────────────────────


def line_hash(source, host, account, computer, event, message, ts):
    payload = f"{source}|{host}|{account}|{computer}|{event}|{message}|{ts}"
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def ingest(source, timestamp, host="", account="", computer="",
           event="Info", message="", severity="Informational"):
    """Insert one normalized record. Returns True when it was new."""
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = host or HOSTNAME
    h = line_hash(source, host, account, computer, event, message, timestamp)
    try:
        conn = _connect()
        cur = conn.execute(
            """INSERT OR IGNORE INTO raw_logs
               (timestamp, source, host, account, computer, event, message,
                severity, line_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (timestamp, source, host, account, computer, event, message,
             severity, h),
        )
        conn.commit()
        inserted = cur.rowcount > 0
        conn.close()
        # Only count *new* records as arrivals. INSERT OR IGNORE returns
        # rowcount 0 for a deduplicated row — feeding those to the rate
        # ring buffer would inflate Events/sec with artificial spikes.
        if inserted:
            MANAGER.record_ingest()
        return inserted
    except sqlite3.OperationalError:
        ensure_schema()
        return False
    except Exception:
        return False


# ─── Runtime statistics (EPS, server health) ────────────────────

SEVERITIES = {
    0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
    4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug",
}

# Documented sliding window used for the live "Events / sec" metric.
EPS_WINDOW_SECONDS = 10


class Stats:
    """In-memory arrival-time ring + server health sampler."""

    def __init__(self):
        self._lock = threading.Lock()
        self._arrivals = deque()
        self._server = {"cpu": 0.0, "memory": 0.0, "disk": 0.0,
                        "active": True, "sampled_at": None}

    # -- ingestion rate -------------------------------------------------
    def record_ingest(self, when=None):
        with self._lock:
            self._arrivals.append(when or time.time())
            cutoff = time.time() - MAX_EPS_HISTORY_SECONDS
            while self._arrivals and self._arrivals[0] < cutoff:
                self._arrivals.popleft()

    def _bucket_counts(self, window=300, bucket=1):
        now = time.time()
        counts = [0] * (window // bucket)
        with self._lock:
            for t in self._arrivals:
                age = now - t
                if 0 <= age < window:
                    idx = int(age // bucket)
                    counts[len(counts) - 1 - idx] += 1
        return counts

    def eps(self):
        """Current events-per-second (EPS_WINDOW_SECONDS sliding window)."""
        with self._lock:
            cutoff = time.time() - EPS_WINDOW_SECONDS
            recent = sum(1 for t in self._arrivals if t >= cutoff)
        return round(recent / float(EPS_WINDOW_SECONDS), 2)

    def max_eps(self):
        buckets = self._bucket_counts(300, 1)
        return max(buckets) if buckets else 0

    def avg_eps(self):
        buckets = self._bucket_counts(300, 1)
        return round(sum(buckets) / len(buckets), 2) if buckets else 0.0

    # -- server health --------------------------------------------------
    def sample_server(self):
        try:
            import psutil

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage(os.path.dirname(DB_PATH) or "/").percent
            with self._lock:
                self._server = {
                    "cpu": round(cpu, 1),
                    "memory": round(mem, 1),
                    "disk": round(disk, 1),
                    "active": True,
                    "sampled_at": datetime.now().isoformat(timespec="seconds"),
                }
        except Exception as ex:
            with self._lock:
                self._server = {
                    "cpu": 0.0, "memory": 0.0, "disk": 0.0,
                    "active": False, "error": str(ex),
                    "sampled_at": datetime.now().isoformat(timespec="seconds"),
                }

    def server(self):
        with self._lock:
            return dict(self._server)


# ─── Collector base ─────────────────────────────────────────────


class BaseCollector(threading.Thread):
    name = "base"
    friendly_name = "Base"

    def __init__(self, manager):
        super().__init__(daemon=True, name=f"collector-{self.name}")
        self.manager = manager
        self.stop_event = threading.Event()
        self.status = "starting"      # active | degraded | inactive | error
        self.detail = "starting…"
        self.ingested = 0
        self.error = None

    def run(self):
        self.status = "active"
        while not self.stop_event.is_set():
            try:
                self.poll()
            except Exception as ex:
                self.error = str(ex)
                self.status = "error"
                self.detail = f"error: {ex}"
            self.stop_event.wait(self.interval)

    interval = COLLECTOR_POLL_SECONDS

    def poll(self):
        raise NotImplementedError

    def stop(self):
        self.stop_event.set()

    def mark_seen(self, extra=None, position=None):
        set_state(self.name, last_position=position,
                  last_seen=datetime.now().isoformat(timespec="seconds"),
                  extra=extra)

    def state(self):
        return get_state(self.name)


# ─── Windows Security event log ─────────────────────────────────

WIN_EVENT_QUERY = (
    '*[System[(EventID=4624 or EventID=4625) '
    'and TimeCreated[timediff(@SystemTime) <= 3600000]]]'
)


class WindowsEventCollector(BaseCollector):
    name = "windows"
    friendly_name = "Windows Security Event Log"
    interval = COLLECTOR_POLL_SECONDS

    def poll(self):
        st = self.state()
        extra = dict(st.get("extra") or {})
        last_ts = extra.get("last_ts")
        new_count = 0

        events = self._read_pywin32(last_ts)
        source_mode = "pywin32"
        if events is None:
            events = self._read_wevtutil()
            source_mode = "wevtutil"
        if events is None:
            # Both read paths failed. Keep the collector 'degraded' (never
            # 'active') and report the *true* reason instead of a generic
            # message, so a broken collector is never shown as healthy.
            self.status = "degraded"
            self.detail = self._failure_detail()
            return

        newest = last_ts
        for ev in events:
            if last_ts and ev["timestamp"] and ev["timestamp"] <= last_ts:
                continue
            if ingest(
                "windows",
                ev["timestamp"],
                host=ev.get("host", ""),
                account=ev.get("account", ""),
                computer=ev.get("computer", ""),
                event=ev["event"],
                message=ev.get("message", ""),
                severity=ev.get("severity", "Informational"),
            ):
                new_count += 1
            if ev["timestamp"] and (not newest or ev["timestamp"] > newest):
                newest = ev["timestamp"]

        if newest and newest != last_ts:
            extra["last_ts"] = newest
        self.ingested += new_count
        self.status = "active"
        self.detail = (
            f"source={source_mode} · 4624/4625 · +{new_count} new "
            f"(total {self.ingested})"
        )
        self.mark_seen(extra=extra)

    # -- pywin32 path ---------------------------------------------------
    def _read_pywin32(self, last_ts):
        try:
            import win32evtlog  # noqa: F401
        except ImportError as ex:
            self._pywin_err = f"pywin32 not installed ({ex})"
            return None
        try:
            import win32evtlog
            import pywintypes

            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            win32evtlog.CloseEventLog(hand)
        except pywintypes.error as ex:
            # Access denied etc. → caller falls back to wevtutil
            self._pywin_err = f"pywin32: {ex}"
            self.error = self._pywin_err
            return None
        except Exception as ex:  # noqa: BLE001 — try wevtutil next
            self._pywin_err = f"pywin32: {type(ex).__name__}: {ex}"
            self.error = self._pywin_err
            return None

        out = []
        for ev in records:
            try:
                eid = int(ev.EventID & 0xFFFF) if isinstance(
                    ev.EventID, int) else None
            except Exception:
                eid = None
            if eid not in (4624, 4625):
                continue
            ts = self._pywin_time(ev.TimeGenerated)
            if not ts:
                continue
            inserts = list(ev.StringInserts or [])
            account = ""
            if len(inserts) > 5:
                account = str(inserts[5] or "").strip()
            if account in ("", "-", "SYSTEM"):
                for i, v in enumerate(inserts):
                    if v and i > 5:
                        account = str(v).strip()
                        break
            computer = str(getattr(ev, "ComputerName", "") or "").strip() or HOSTNAME
            out.append({
                "timestamp": ts,
                "host": computer,
                "account": account,
                "computer": computer,
                "event": "Success" if eid == 4624 else "Failure",
                "message": f"EventID {eid}: " + "; ".join(
                    str(x) for x in inserts if x
                ),
                "severity": "Informational" if eid == 4624 else "FailureAudit",
            })
        return out

    @staticmethod
    def _pywin_time(t):
        if t is None:
            return None
        try:
            return t.Format("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        try:
            return datetime.fromtimestamp(
                time.mktime(t.timetuple()) if hasattr(t, "timetuple") else t
            ).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    # -- wevtutil fallback ----------------------------------------------
    def _read_wevtutil(self):
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", "Security", "/q:" + WIN_EVENT_QUERY,
                 "/f:text", "/rd:true", "/c:1000"],
                capture_output=True, text=True, timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError as ex:
            self._wevt_err = f"wevtutil not found ({ex})"
            return None
        except Exception as ex:  # noqa: BLE001 — report and stay degraded
            self._wevt_err = f"wevtutil: {type(ex).__name__}: {ex}"
            return None
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()[:200]
            self._wevt_err = f"wevtutil rc={proc.returncode}: {err}"
            return None
        return self._parse_wevtutil(proc.stdout)

    @staticmethod
    def _parse_wevtutil(text):
        events = []
        for block in re.split(r"\r?\n\r?\n", text):
            block = block.strip()
            if not block.startswith("Event["):
                continue
            fields = {}
            msg_lines = []
            in_msg = False
            for ln in block.splitlines():
                if in_msg:
                    msg_lines.append(ln)
                    continue
                m = re.match(r"^(Log Name|Source|Date|Event ID|Task|Level|"
                             r"Opcode|Keyword|User|Computer)\s*:\s*(.*)$", ln)
                if m:
                    key = m.group(1).strip()
                    if key == "Message":
                        in_msg = True
                        msg_lines.append(m.group(2))
                    else:
                        fields[key] = m.group(2).strip()
            eid = fields.get("Event ID", "")
            if eid not in ("4624", "4625"):
                continue
            ts = parse_ts_flexible(fields.get("Date", ""))
            if not ts:
                continue
            user = fields.get("User", "").strip()
            computer = fields.get("Computer", "").strip() or HOSTNAME
            message = "\n".join(msg_lines).strip()
            if user in ("", "-"):
                mm = re.search(r"Account Name\s*:\s*(\S+)", message)
                if mm:
                    user = mm.group(1).strip()
            events.append({
                "timestamp": ts,
                "host": computer,
                "account": user,
                "computer": computer,
                "event": "Success" if eid == "4624" else "Failure",
                "message": message,
                "severity": "Informational" if eid == "4624" else "FailureAudit",
            })
        return events

    def _failure_detail(self):
        """Explain why the Security log could not be read (never hide it)."""
        py = getattr(self, "_pywin_err", "") or "pywin32 read failed"
        wv = getattr(self, "_wevt_err", "") or "wevtutil read failed"
        blob = f"{py} {wv}".lower()
        if ("access is denied" in blob or "rc=5" in blob
                or "privilege is not held" in blob or "privilege not held" in blob):
            return ("Security event log access denied — LabTrace must run as "
                    "Administrator (elevated) to read event IDs 4624/4625. "
                    f"Details: {py}; {wv}")
        if "not installed" in py.lower() and "not found" in wv.lower():
            return ("Windows Security log collector unavailable — pywin32 is "
                    "not installed and wevtutil was not found. Install it "
                    "with: pip install pywin32")
        return (f"Windows Security log collector degraded. "
                f"Details: {py}; {wv}")


# ─── Unix auth log / journalctl ─────────────────────────────────

AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/system.log",
]


class UnixAuthCollector(BaseCollector):
    name = "auth_log"
    friendly_name = "Unix Auth Log"
    interval = COLLECTOR_POLL_SECONDS

    def poll(self):
        path = self._pick_log()
        if path:
            self._tail_file(path)
        else:
            self._journalctl()

    def _pick_log(self):
        for p in AUTH_LOG_CANDIDATES:
            if os.path.isfile(p) and os.access(p, os.R_OK):
                return p
        return None

    def _tail_file(self, path):
        offset = self.state().get("last_position", 0)
        try:
            size = os.path.getsize(path)
        except OSError:
            self.status = "degraded"
            self.detail = f"cannot stat {path}"
            return
        if size < offset:  # rotated / truncated
            offset = 0
        if size == offset:
            self.status = "active"
            self.detail = f"tailing {path} · no new lines"
            self.mark_seen()
            return

        try:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read()
        except OSError as ex:
            self.status = "degraded"
            self.detail = f"read error: {ex}"
            return

        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return
        new_offset = offset + last_nl + 1
        text = data[: last_nl + 1].decode("utf-8", "replace")
        new_count = 0
        for line in text.splitlines():
            rec = parse_syslog_line(line)
            if not rec:
                continue
            if ingest("auth_log", rec["timestamp"], host=rec["host"],
                      account=rec["account"], computer=rec["computer"],
                      event=rec["event"], message=rec["message"],
                      severity=rec["severity"]):
                new_count += 1
        self.ingested += new_count
        self.status = "active"
        self.detail = f"tailing {path} · +{new_count} new (total {self.ingested})"
        self.mark_seen(position=new_offset)

    def _journalctl(self):
        st = self.state()
        extra = dict(st.get("extra") or {})
        last_ts = extra.get("last_ts")
        since = last_ts or (datetime.now() - timedelta(minutes=30)).isoformat()
        try:
            proc = subprocess.run(
                ["journalctl", "--output=short-iso", "--since", since,
                 "--no-pager", "-n", "1000"],
                capture_output=True, text=True, timeout=60,
            )
        except (FileNotFoundError, OSError) as ex:
            self.status = "inactive"
            self.detail = f"no readable auth log and journalctl unavailable ({ex})"
            return
        if proc.returncode != 0:
            self.status = "inactive"
            self.detail = f"journalctl rc={proc.returncode}"
            return

        newest = last_ts
        new_count = 0
        for line in proc.stdout.splitlines():
            rec = parse_syslog_line(line)
            if not rec:
                continue
            if last_ts and rec["timestamp"] <= last_ts:
                continue
            if ingest("auth_log", rec["timestamp"], host=rec["host"],
                      account=rec["account"], computer=rec["computer"],
                      event=rec["event"], message=rec["message"],
                      severity=rec["severity"]):
                new_count += 1
            if rec["timestamp"] > (newest or ""):
                newest = rec["timestamp"]
        if newest and newest != last_ts:
            extra["last_ts"] = newest
        self.ingested += new_count
        self.status = "active"
        self.detail = f"journalctl · +{new_count} new (total {self.ingested})"
        self.mark_seen(extra=extra)


# ─── Watched folder: data/incoming/ ────────────────────────────

CSV_HEADER = ("event_id", "timestamp", "account", "computer", "event",
              "department_case")


class FileWatchCollector(BaseCollector):
    name = "file_watch"
    friendly_name = "Watched Folder (data/incoming)"
    interval = COLLECTOR_POLL_SECONDS

    def poll(self):
        if not os.path.isdir(INCOMING_DIR):
            os.makedirs(INCOMING_DIR, exist_ok=True)
        files = sorted(
            f for f in os.listdir(INCOMING_DIR)
            if f.lower().endswith((".csv", ".log"))
            and os.path.isfile(os.path.join(INCOMING_DIR, f))
        )
        total_new = 0
        for fname in files:
            total_new += self._process_file(fname)
        self.ingested += total_new
        self.status = "active"
        self.detail = (
            f"watching {INCOMING_DIR} · {len(files)} file(s) · "
            f"+{total_new} new (total {self.ingested})"
        )
        self.mark_seen()

    def _process_file(self, fname):
        path = os.path.join(INCOMING_DIR, fname)
        key = f"file:{path}"
        st = get_state(key)
        offset = st.get("last_position", 0)
        try:
            size = os.path.getsize(path)
        except OSError:
            return 0
        if size < offset:  # rotated / truncated
            offset = 0
        if size == offset:
            return 0

        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return 0  # wait for a complete line
        chunk = data[: last_nl + 1].decode("utf-8", "replace")
        new_offset = offset + last_nl + 1

        new_count = 0
        if fname.lower().endswith(".csv"):
            new_count = self._parse_csv(chunk)
        else:
            new_count = self._parse_log(chunk)
        set_state(key, last_position=new_offset,
                  last_seen=datetime.now().isoformat(timespec="seconds"))
        return new_count

    def _parse_csv(self, chunk):
        count = 0
        for row in csv.reader(chunk.splitlines()):
            if not row:
                continue
            cells = [c.strip() for c in row]
            if cells[0].lower() == "event_id":
                continue  # header
            rec = dict(zip(CSV_HEADER, cells))
            ts = parse_ts_flexible(rec.get("timestamp", ""))
            if not ts:
                continue
            event = rec.get("event", "").strip().capitalize()
            if event not in ("Failure", "Success"):
                event = "Info"
            if ingest(
                "file", ts,
                host=rec.get("computer", "") or HOSTNAME,
                account=rec.get("account", ""),
                computer=rec.get("computer", ""),
                event=event,
                message=f"event_id={rec.get('event_id', '')} "
                        f"department={rec.get('department_case', '')}",
                severity="Informational",
            ):
                count += 1
        return count

    def _parse_log(self, chunk):
        count = 0
        for line in chunk.splitlines():
            if not line.strip():
                continue
            rec = parse_syslog_line(line) or parse_pipe_line(line)
            if rec:
                if ingest("file", rec["timestamp"], host=rec["host"],
                          account=rec["account"], computer=rec["computer"],
                          event=rec["event"], message=rec["message"],
                          severity=rec["severity"]):
                    count += 1
            else:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if ingest("file", ts, host=HOSTNAME, computer=HOSTNAME,
                          event="Info", message=line,
                          severity="Informational"):
                    count += 1
        return count


# ─── UDP syslog receiver (port 5140) ──────────────────────────

SYSLOG_PRI_RE = re.compile(r"^<(\d{1,3})>")


class SyslogUDPReceiver(BaseCollector):
    name = "syslog_udp"
    friendly_name = "Syslog UDP Receiver"
    interval = 1  # not used; loop driven by socket timeout

    def __init__(self, manager):
        super().__init__(manager)
        self.packets = 0
        self.sock = None

    def run(self):
        self.status = "active"
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", SYSLOG_PORT))
            self.sock.settimeout(SYSLOG_THREAD_TIMEOUT)
        except OSError as ex:
            self.status = "error"
            self.detail = f"cannot bind UDP/{SYSLOG_PORT}: {ex}"
            return
        self.detail = f"listening on UDP/{SYSLOG_PORT}"
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle(data, addr)
        try:
            self.sock.close()
        except Exception:
            pass

    def _handle(self, data, addr):
        try:
            text = data.decode("utf-8", "replace").strip()
        except Exception:
            return
        self.packets += 1
        pri = None
        m = SYSLOG_PRI_RE.match(text)
        if m:
            pri = int(m.group(1))
            text = text[m.end():].strip()
        severity = SEVERITIES.get((pri % 8) if pri is not None else 6,
                                  "Informational")

        # RFC5424: <34>1 2025-03-10T09:05:12.000Z host app proc [sd] msg
        rfc5424 = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
            r"\s+(\S+)\s+\S+\s+\S+(?:\s+\S+)?\s*(.*)$", text)
        rec = None
        if rfc5424:
            ts = parse_ts_flexible(rfc5424.group(1))
            rec = {
                "timestamp": ts,
                "host": rfc5424.group(2),
                "message": rfc5424.group(3),
            }
        else:
            # RFC3164: Oct 11 22:14:15 host tag: msg  (or bare msg)
            m3164 = re.match(
                r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
                r"(\S+)\s+\S+?(?:\[\d+\])?:\s*(.*)$", text)
            if m3164:
                rec = {
                    "timestamp": parse_ts_flexible(m3164.group(1)),
                    "host": m3164.group(2),
                    "message": m3164.group(3),
                }
        if not rec:
            rec = {"timestamp": None, "host": addr[0], "message": text}

        ts = rec["timestamp"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event, account = classify_message(rec["message"])
        ingest(
            "syslog_udp", ts,
            host=rec["host"] or addr[0],
            account=account,
            computer=rec["host"] or addr[0],
            event=event,
            message=rec["message"],
            severity=severity,
        )
        if self.packets % 25 == 0:
            self.detail = f"listening on UDP/{SYSLOG_PORT} · {self.packets} packets"
            self.mark_seen()

    def poll(self):  # unused; loop is socket driven
        pass


# ─── Server health sampler ───────────────────────────────────────


class ServerMonitor(threading.Thread):
    def __init__(self, stats):
        super().__init__(daemon=True, name="server-monitor")
        self.stats = stats
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            self.stats.sample_server()
            self.stop_event.wait(SERVER_SAMPLE_SECONDS)

    def stop(self):
        self.stop_event.set()


# ─── Manager ─────────────────────────────────────────────────────


class CollectorManager:
    def __init__(self):
        self.stats = Stats()
        self._threads = []
        self._started = False
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self._started:
                return self
            ensure_schema()
            self._threads = []
            if sys.platform == "win32":
                self._threads.append(WindowsEventCollector(self))
            else:
                self._threads.append(UnixAuthCollector(self))
            self._threads.append(FileWatchCollector(self))
            self._threads.append(SyslogUDPReceiver(self))
            self._threads.append(ServerMonitor(self.stats))
            for t in self._threads:
                t.start()
            self._started = True
        return self

    def stop(self):
        with self._lock:
            for t in self._threads:
                try:
                    t.stop()
                except Exception:
                    pass
            self._started = False

    def join(self, timeout=5):
        for t in list(self._threads):
            t.join(timeout=timeout)

    # -- status for the monitor API -------------------------------------
    def status(self):
        rows = []
        for t in self._threads:
            if isinstance(t, ServerMonitor):
                continue
            st = get_state(t.name)
            rows.append({
                "key": t.name,
                "name": t.friendly_name,
                "status": t.status,
                "detail": t.detail,
                "lastSeen": st.get("last_seen"),
                "ingested": getattr(t, "ingested", 0),
                "packets": getattr(t, "packets", None),
            })
        return rows

    def server(self):
        return self.stats.server()

    def eps_stats(self):
        return {
            "eps": self.stats.eps(),
            "maxEps": self.stats.max_eps(),
            "avgEps": self.stats.avg_eps(),
        }

    # exposed to ingest()
    def record_ingest(self, when=None):
        self.stats.record_ingest(when)


MANAGER = CollectorManager()


def start_collector():
    """Start all collector threads (idempotent). Returns the manager."""
    return MANAGER.start()


def stop_collector():
    MANAGER.stop()
