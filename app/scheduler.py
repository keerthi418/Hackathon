"""
LabTrace · LogLens — Live Detection Scheduler

Every 30 seconds (APScheduler) this job:

  1. Takes the new rows from `raw_logs` (position tracked in
     collector_state so restarts never re-process old rows).
  2. Merges them with the manually uploaded events (`events` table)
     and runs the existing detect_cases() engine (R1 / R2) with the
     N, W and lab-hours settings from the `settings` table.
  3. Creates / updates cases in the `cases` table (upsert by
     case_key). Human decisions are never overwritten: a confirmed or
     dismissed case keeps its status.
  4. Flags new or escalated cases (is_new=1) so the dashboard and the
     Live Monitor can show a live alert banner.
  5. Auto-deletes raw logs older than RETENTION_DAYS (default 30).

Detection never blocks anything — Confirm / Dismiss stays human-only.
"""
import sqlite3
import threading
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import DB_PATH, DETECT_INTERVAL_SECONDS, RETENTION_DAYS
from app.collector import ensure_schema, get_state, set_state
from app.engine import detect_cases

# ─── DB helper (own connection per call → thread safe) ──────────


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_cases_table():
    """Add live-monitoring columns to an existing cases table."""
    conn = _connect()
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(cases)")]
        for col, ddl in (
            ("created_at", "TEXT"),
            ("updated_at", "TEXT"),
            ("origin", "TEXT DEFAULT 'manual'"),
            ("is_new", "INTEGER DEFAULT 0"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {ddl}")
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_key "
                "ON cases(case_key)"
            )
        except sqlite3.IntegrityError:
            # legacy duplicate keys → keep the oldest row
            conn.execute(
                "DELETE FROM cases WHERE id NOT IN "
                "(SELECT MIN(id) FROM cases GROUP BY case_key)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_key "
                "ON cases(case_key)"
            )
        conn.commit()
    finally:
        conn.close()


def _settings():
    conn = _connect()
    try:
        s = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        return {
            "N": s["n_threshold"] if s else 3,
            "W": s["w_minutes"] if s else 5,
            "open": s["open_time"] if s else "08:30",
            "close": s["close_time"] if s else "17:30",
        }
    finally:
        conn.close()


def _merged_events(conn):
    """raw_logs (live) + events (manual uploads).

    raw_logs rows are already deduplicated by line_hash at ingest time, and
    the events table is wiped on every upload — so we simply concatenate.
    NOTE: we must NOT dedup by (account, computer, timestamp, event):
    distinct events can share the same second (e.g. 5 failures in one
    second) and collapsing them would break the R1 burst detection.
    """
    events = []

    for r in conn.execute(
        "SELECT id, timestamp, account, computer, event FROM raw_logs ORDER BY id"
    ):
        events.append({
            "event_id": f"raw:{r['id']}",
            "timestamp": r["timestamp"],
            "account": r["account"],
            "computer": r["computer"],
            "event": r["event"],
            "department_case": "",
        })

    for r in conn.execute(
        "SELECT event_id, timestamp, account, computer, event, department_case "
        "FROM events ORDER BY id"
    ):
        events.append({
            "event_id": r["event_id"],
            "timestamp": r["timestamp"],
            "account": r["account"],
            "computer": r["computer"],
            "event": r["event"],
            "department_case": r["department_case"],
        })
    return events


def run_detection():
    """Single detection pass. Returns (new_rows, cases_created, cases_updated)."""
    ensure_schema()
    migrate_cases_table()

    conn = _connect()
    try:
        st = get_state("detector")
        last_id = st.get("last_position", 0) or 0

        rows = conn.execute(
            "SELECT id FROM raw_logs WHERE id > ? ORDER BY id", (last_id,)
        ).fetchall()
        if not rows:
            return 0, 0, 0
        new_last = rows[-1]["id"]

        settings = _settings()
        events = _merged_events(conn)
        if not events:
            set_state("detector", last_position=new_last)
            return len(rows), 0, 0

        cases = detect_cases(
            events,
            N=settings["N"], W=settings["W"],
            open_time=settings["open"], close_time=settings["close"],
        )

        created = updated = 0
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for c in cases:
            existing = conn.execute(
                "SELECT id, status, priority, event_count, is_new FROM cases "
                "WHERE case_key=?",
                (c["case_key"],),
            ).fetchone()

            if existing is None:
                conn.execute(
                    """INSERT INTO cases
                       (case_key, account, computer, department, priority, r1, r2,
                        reason, human_check, event_count, matched_event_ids,
                        r1_detail, r2_detail, status, created_at, updated_at,
                        origin, is_new)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        c["case_key"], c["account"], c["computer"],
                        c["department"], c["priority"],
                        1 if c["r1"] else 0, 1 if c["r2"] else 0,
                        c["reason"], c.get("human_check"), c["event_count"],
                        __import__("json").dumps(c.get("matched_event_ids", [])),
                        __import__("json").dumps(c.get("r1_detail") or {}),
                        __import__("json").dumps(c.get("r2_detail") or {}),
                        "open", now, now, "live", 1,
                    ),
                )
                created += 1
            else:
                # never overwrite a human decision
                keep_status = existing["status"] if existing["status"] in (
                    "confirmed", "dismissed") else "open"
                escalated = (
                    existing["priority"] != c["priority"]
                    or existing["event_count"] != c["event_count"]
                )
                conn.execute(
                    """UPDATE cases SET
                       priority=?, r1=?, r2=?, reason=?, human_check=?,
                       event_count=?, matched_event_ids=?, r1_detail=?,
                       r2_detail=?, status=?, updated_at=?, origin='live',
                       is_new = CASE WHEN ?=1 THEN 1 ELSE COALESCE(is_new, 0) END
                       WHERE id=?""",
                    (
                        c["priority"], 1 if c["r1"] else 0, 1 if c["r2"] else 0,
                        c["reason"], c.get("human_check"), c["event_count"],
                        __import__("json").dumps(c.get("matched_event_ids", [])),
                        __import__("json").dumps(c.get("r1_detail") or {}),
                        __import__("json").dumps(c.get("r2_detail") or {}),
                        keep_status, now, 1 if escalated else 0, existing["id"],
                    ),
                )
                if escalated:
                    updated += 1

        conn.commit()
        set_state("detector", last_position=new_last)

        if created or updated:
            try:
                conn.execute(
                    "INSERT INTO audit_log (user_id, action, details) "
                    "VALUES (?,?,?)",
                    (None, "AUTO_DETECT",
                     f"new_rows={len(rows)} created={created} updated={updated}"),
                )
                conn.commit()
            except Exception:
                pass
        return len(rows), created, updated
    finally:
        conn.close()


def cleanup_raw_logs():
    """Delete raw logs older than RETENTION_DAYS (local-time comparison)."""
    cutoff = (datetime.now() - timedelta(days=RETENTION_DAYS)).strftime(
        "%Y-%m-%d %H:%M:%S")
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM raw_logs WHERE timestamp < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ─── Scheduler lifecycle ────────────────────────────────────────

_scheduler = None
_lock = threading.Lock()


def start_scheduler():
    """Start the APScheduler background scheduler (idempotent)."""
    global _scheduler
    with _lock:
        if _scheduler is not None:
            return _scheduler
        ensure_schema()
        migrate_cases_table()

        sched = BackgroundScheduler(daemon=True)
        sched.add_job(
            run_detection, "interval", seconds=DETECT_INTERVAL_SECONDS,
            id="live-detect", max_instances=1, coalesce=True,
        )
        sched.add_job(
            cleanup_raw_logs, "interval", hours=1,
            id="retention", max_instances=1, coalesce=True,
        )
        # backfill immediately on startup so the monitor has data
        sched.add_job(
            run_detection, "date",
            run_date=datetime.now() + timedelta(seconds=5),
            id="live-detect-bootstrap",
        )
        sched.start()
        _scheduler = sched
    return _scheduler


def stop_scheduler():
    global _scheduler
    with _lock:
        if _scheduler is not None:
            _scheduler.shutdown(wait=False)
            _scheduler = None
