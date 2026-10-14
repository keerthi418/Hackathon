"""
LabTrace · LogLens — Live Detection Scheduler

Every 30 seconds (APScheduler) this job:

  1. Takes the new rows from `raw_logs` (position tracked in
     collector_state so restarts never re-process old rows).
  2. Merges them with the manually uploaded events (`events` table)
     and runs the existing detect_cases() engine (R1–R6) with the
     N, W, lab-hours and R4–R6 settings from the `settings` table.
  3. Creates / updates cases in the `cases` table (upsert by
     case_key). Human decisions are never overwritten: a confirmed or
     dismissed case keeps its status.
  4. Records every rule occurrence in `rule_matches` (deduplicated
     by a deterministic fingerprint) so R6 can detect recurrence
     without counting duplicate scheduler runs as new incidents.
  5. Flags new or escalated cases (is_new=1) so the dashboard and the
     Live Monitor can show a live alert banner.
  6. Auto-deletes raw logs older than RETENTION_DAYS (default 30).

Detection never blocks anything — Confirm / Dismiss stays human-only.
"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import DB_PATH, DETECT_INTERVAL_SECONDS, RETENTION_DAYS
from app.collector import ensure_schema, get_state, set_state
from app.engine import detect_cases, fingerprint

# ─── DB helper (own connection per call → thread safe) ──────────


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_cases_table():
    """Add live-monitoring + R3–R6 columns to an existing cases table."""
    conn = _connect()
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(cases)")]
        new_cols = (
            ("created_at", "TEXT"),
            ("updated_at", "TEXT"),
            ("origin", "TEXT DEFAULT 'manual'"),
            ("is_new", "INTEGER DEFAULT 0"),
            # R3–R6 flags
            ("r3", "INTEGER DEFAULT 0"),
            ("r4", "INTEGER DEFAULT 0"),
            ("r5", "INTEGER DEFAULT 0"),
            ("r6", "INTEGER DEFAULT 0"),
            # R3–R6 detail payloads (JSON)
            ("r3_detail", "TEXT"),
            ("r4_detail", "TEXT"),
            ("r5_detail", "TEXT"),
            ("r6_detail", "TEXT"),
            # explainability / triage helpers
            ("rules", "TEXT"),
            ("rule_details", "TEXT"),
            ("severity", "TEXT"),
            ("score", "INTEGER DEFAULT 0"),
        )
        for col, ddl in new_cols:
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


def migrate_settings_table():
    """Add R4–R6 threshold columns to the settings table."""
    conn = _connect()
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(settings)")]
        for col, ddl in (
            ("r4_window", "INTEGER DEFAULT 10"),
            ("r5_threshold", "INTEGER DEFAULT 4"),
            ("r5_window", "INTEGER DEFAULT 10"),
            ("r6_threshold", "INTEGER DEFAULT 2"),
            ("r6_hours", "INTEGER DEFAULT 24"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE settings ADD COLUMN {col} {ddl}")
        conn.commit()
    finally:
        conn.close()


def migrate_rule_matches():
    """Create the rule-occurrence store used by R6 (idempotent)."""
    conn = _connect()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rule_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_set TEXT,
                account TEXT,
                computer TEXT,
                first_ts TEXT,
                last_ts TEXT,
                fingerprint TEXT UNIQUE,
                matched_event_ids TEXT,
                detail TEXT,
                case_key TEXT,
                origin TEXT DEFAULT 'live',
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_rm_acct_comp
                ON rule_matches(account, computer);
            CREATE INDEX IF NOT EXISTS idx_rm_last
                ON rule_matches(last_ts);
        """)
        conn.commit()
    finally:
        conn.close()


def _settings():
    conn = _connect()
    try:
        s = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        if not s:
            return {
                "N": 3, "W": 5, "open": "08:30", "close": "17:30",
                "r4_window": 10, "r5_threshold": 4, "r5_window": 10,
                "r6_threshold": 2, "r6_hours": 24,
            }
        return {
            "N": s["n_threshold"] if s["n_threshold"] is not None else 3,
            "W": s["w_minutes"] if s["w_minutes"] is not None else 5,
            "open": s["open_time"] or "08:30",
            "close": s["close_time"] or "17:30",
            "r4_window": s["r4_window"] if s["r4_window"] is not None else 10,
            "r5_threshold": (s["r5_threshold"]
                             if s["r5_threshold"] is not None else 4),
            "r5_window": s["r5_window"] if s["r5_window"] is not None else 10,
            "r6_threshold": (s["r6_threshold"]
                             if s["r6_threshold"] is not None else 2),
            "r6_hours": s["r6_hours"] if s["r6_hours"] is not None else 24,
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


def get_prior_matches():
    """Stored rule occurrences for R6 (deterministic de-duplication)."""
    conn = _connect()
    try:
        rows = conn.execute(
            """SELECT rule_set, account, computer, first_ts, last_ts,
                      fingerprint, case_key, matched_event_ids
               FROM rule_matches"""
        ).fetchall()
        out = []
        for r in rows:
            try:
                ids = json.loads(r["matched_event_ids"] or "[]")
            except Exception:
                ids = []
            out.append({
                "rule_set": r["rule_set"] or "",
                "account": r["account"] or "",
                "computer": r["computer"] or "",
                "first_ts": r["first_ts"],
                "last_ts": r["last_ts"],
                "fingerprint": r["fingerprint"],
                "case_key": r["case_key"],
                "matched_event_ids": ids,
            })
        return out
    finally:
        conn.close()


def _record_match(conn, c, origin):
    """Persist one rule occurrence (INSERT OR IGNORE → a repeated
    scheduler run over unchanged data never creates a second row)."""
    matched = c.get("matched_event_ids") or []
    events = c.get("events") or []
    ts_list = [e["timestamp"] for e in events if e.get("timestamp")]
    first_ts = min(ts_list) if ts_list else None
    last_ts = max(ts_list) if ts_list else None
    fp = fingerprint(c.get("account", ""), c.get("computer", ""), matched)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """INSERT OR IGNORE INTO rule_matches
           (rule_set, account, computer, first_ts, last_ts, fingerprint,
            matched_event_ids, detail, case_key, origin, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ",".join(c.get("rules") or []),
            c.get("account", ""),
            c.get("computer", ""),
            first_ts,
            last_ts,
            fp,
            json.dumps(matched),
            json.dumps(c.get("rule_details") or []),
            c.get("case_key", ""),
            origin,
            now,
        ),
    )


def backfill_legacy_cases():
    """Refresh cases created by an older engine.

    A case is "legacy" when a rule flag (r1–r6) is set but the new
    `rules` / `rule_details` explainability columns are empty. In
    that case we reset the detector cursor to 0 so the next
    detection pass reprocesses every raw_logs row and upserts each
    case with the full R1–R6 explanation, score and severity.
    Returns the number of legacy cases found."""
    conn = _connect()
    try:
        legacy = conn.execute(
            """SELECT COUNT(*) FROM cases
               WHERE (COALESCE(r1,0)=1 OR COALESCE(r2,0)=1
                      OR COALESCE(r3,0)=1 OR COALESCE(r4,0)=1
                      OR COALESCE(r5,0)=1 OR COALESCE(r6,0)=1)
                 AND (rules IS NULL OR rule_details IS NULL)"""
        ).fetchone()[0]
        if legacy:
            conn.execute(
                "UPDATE collector_state SET last_position=0 "
                "WHERE source='detector'")
            conn.commit()
        return legacy
    finally:
        conn.close()


def run_detection():
    """Single detection pass. Returns (new_rows, cases_created, cases_updated)."""
    ensure_schema()
    migrate_cases_table()
    migrate_settings_table()
    migrate_rule_matches()

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

        prior_matches = get_prior_matches()
        cases = detect_cases(
            events,
            N=settings["N"], W=settings["W"],
            open_time=settings["open"], close_time=settings["close"],
            r4_window=settings["r4_window"],
            r5_threshold=settings["r5_threshold"],
            r5_window=settings["r5_window"],
            r6_threshold=settings["r6_threshold"],
            r6_hours=settings["r6_hours"],
            prior_matches=prior_matches,
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
                       (case_key, account, computer, department, priority,
                        severity, score, r1, r2, r3, r4, r5, r6,
                        reason, human_check, event_count, matched_event_ids,
                        r1_detail, r2_detail, r3_detail, r4_detail,
                        r5_detail, r6_detail, rules, rule_details,
                        status, created_at, updated_at, origin, is_new)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        c["case_key"], c["account"], c["computer"],
                        c["department"], c["priority"],
                        c.get("severity", "Low"), c.get("score", 0),
                        1 if c["r1"] else 0, 1 if c["r2"] else 0,
                        1 if c["r3"] else 0, 1 if c["r4"] else 0,
                        1 if c["r5"] else 0, 1 if c["r6"] else 0,
                        c["reason"], c.get("human_check"), c["event_count"],
                        json.dumps(c.get("matched_event_ids", [])),
                        json.dumps(c.get("r1_detail") or {}),
                        json.dumps(c.get("r2_detail") or {}),
                        json.dumps(c.get("r3_detail") or {}),
                        json.dumps(c.get("r4_detail") or {}),
                        json.dumps(c.get("r5_detail") or {}),
                        json.dumps(c.get("r6_detail") or {}),
                        ",".join(c.get("rules") or []),
                        json.dumps(c.get("rule_details") or []),
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
                       priority=?, severity=?, score=?,
                       r1=?, r2=?, r3=?, r4=?, r5=?, r6=?,
                       reason=?, human_check=?,
                       event_count=?, matched_event_ids=?,
                       r1_detail=?, r2_detail=?, r3_detail=?,
                       r4_detail=?, r5_detail=?, r6_detail=?,
                       rules=?, rule_details=?,
                       status=?, updated_at=?, origin='live',
                       is_new = CASE WHEN ?=1 THEN 1 ELSE COALESCE(is_new, 0) END
                       WHERE id=?""",
                    (
                        c["priority"], c.get("severity", "Low"),
                        c.get("score", 0),
                        1 if c["r1"] else 0, 1 if c["r2"] else 0,
                        1 if c["r3"] else 0, 1 if c["r4"] else 0,
                        1 if c["r5"] else 0, 1 if c["r6"] else 0,
                        c["reason"], c.get("human_check"), c["event_count"],
                        json.dumps(c.get("matched_event_ids", [])),
                        json.dumps(c.get("r1_detail") or {}),
                        json.dumps(c.get("r2_detail") or {}),
                        json.dumps(c.get("r3_detail") or {}),
                        json.dumps(c.get("r4_detail") or {}),
                        json.dumps(c.get("r5_detail") or {}),
                        json.dumps(c.get("r6_detail") or {}),
                        ",".join(c.get("rules") or []),
                        json.dumps(c.get("rule_details") or []),
                        keep_status, now, 1 if escalated else 0, existing["id"],
                    ),
                )
                if escalated:
                    updated += 1

            # record the occurrence for R6 recurrence detection
            _record_match(conn, c, "live")

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
        # rule occurrence history only needs to outlive the R6 window (24 h);
        # keep it for the same retention period for auditability.
        conn.execute("DELETE FROM rule_matches WHERE last_ts < ?", (cutoff,))
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
        migrate_settings_table()
        migrate_rule_matches()
        # refresh cases written by an older engine so every
        # alert carries its R1–R6 explanation
        backfill_legacy_cases()

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
