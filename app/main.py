"""
LabTrace · LogLens — Secure Flask Cybersecurity Log Analysis
CYBERHACK Edition with 2FA, Register, Forgot Password
"""
import os
import csv
import io
import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64

from flask import (
    Flask, request, session, redirect, url_for, render_template,
    jsonify, flash, send_file, g
)
from werkzeug.utils import secure_filename

from app.config import BASE_DIR, DB_PATH, SAMPLE_CSV
from app.engine import (
    detect_cases, parse_ts,
    RULE_NAMES, RULE_SEVERITY, RULE_RECOMMENDATIONS,
)
from app.collector import MANAGER, ensure_schema, EPS_WINDOW_SECONDS
from app.scheduler import (
    migrate_cases_table, migrate_settings_table,
    migrate_rule_matches, get_prior_matches, _record_match,
    backfill_legacy_cases,
)

# ─── Config ─────────────────────────────────────────
UPLOAD_MAX = 2 * 1024 * 1024  # 2 MB
TS_FMT = "%Y-%m-%d %H:%M:%S"

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = UPLOAD_MAX
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)


# ─── DB helpers ─────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT NOT NULL DEFAULT 'analyst',
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            reset_token TEXT,
            reset_expires TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            open_time TEXT DEFAULT '08:30',
            close_time TEXT DEFAULT '17:30',
            n_threshold INTEGER DEFAULT 3,
            w_minutes INTEGER DEFAULT 5,
            r4_window INTEGER DEFAULT 10,
            r5_threshold INTEGER DEFAULT 4,
            r5_window INTEGER DEFAULT 10,
            r6_threshold INTEGER DEFAULT 2,
            r6_hours INTEGER DEFAULT 24
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            timestamp TEXT,
            account TEXT,
            computer TEXT,
            event TEXT,
            department_case TEXT
        );
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_key TEXT,
            account TEXT,
            computer TEXT,
            department TEXT,
            priority TEXT,
            severity TEXT,
            score INTEGER DEFAULT 0,
            r1 INTEGER,
            r2 INTEGER,
            r3 INTEGER DEFAULT 0,
            r4 INTEGER DEFAULT 0,
            r5 INTEGER DEFAULT 0,
            r6 INTEGER DEFAULT 0,
            reason TEXT,
            human_check TEXT,
            event_count INTEGER,
            matched_event_ids TEXT,
            r1_detail TEXT,
            r2_detail TEXT,
            r3_detail TEXT,
            r4_detail TEXT,
            r5_detail TEXT,
            r6_detail TEXT,
            rules TEXT,
            rule_details TEXT,
            status TEXT DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            prev_hash TEXT DEFAULT 'GENESIS',
            entry_hash TEXT DEFAULT ''
        );
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
    """)
    # live-monitoring columns on cases (safe on existing DBs)
    migrate_cases_table()
    migrate_settings_table()
    migrate_rule_matches()
    ensure_schema()
    # Add hash-chain columns to audit_log if missing (safe migration)
    audit_cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_log)")}
    if "prev_hash" not in audit_cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT DEFAULT 'GENESIS'")
    if "entry_hash" not in audit_cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT ''")
    # refresh legacy cases (old engine) so every alert is
    # explainable; the scheduler reprocesses raw_logs next
    backfill_legacy_cases()
    # seed settings
    if not c.execute("SELECT id FROM settings WHERE id=1").fetchone():
        c.execute("INSERT INTO settings (id) VALUES (1)")
    # seed users
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for u, p, name, role in [
            ("admin", "LabTrace@2025", "Lab Supervisor", "admin"),
            ("analyst", "Analyst@2025", "Security Analyst", "analyst"),
        ]:
            h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
            c.execute(
                "INSERT INTO users (username, password_hash, display_name, role) VALUES (?,?,?,?)",
                (u, h, name, role),
            )
    conn.commit()
    conn.close()


def _audit_hash(user_id, action, details, created_at):
    """Compute SHA-256 hash chain for audit integrity verification."""
    import hashlib
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["entry_hash"] if row else "GENESIS"
    except Exception:
        prev_hash = "GENESIS"
    finally:
        conn.close()
    payload = f"{prev_hash}|{user_id}|{action}|{details}|{created_at}"
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def audit(user_id, action, details=""):
    """Record an audit log entry with hash-chain integrity verification.

    Each entry includes a SHA-256 hash chaining it to the previous entry,
    creating a tamper-evident audit trail. Passwords, session secrets,
    and API keys are never recorded.
    """
    try:
        conn = get_db()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_hash = _audit_hash(user_id, action, details, now)
        conn.execute(
            "INSERT INTO audit_log (user_id, action, details, created_at, prev_hash, entry_hash) "
            "VALUES (?,?,?,?,?,?)",
            (user_id, action, details, now, 
             _audit_prev_hash(), entry_hash),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _audit_prev_hash():
    """Get the hash of the last audit entry (for chain verification)."""
    import hashlib
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else "GENESIS"
    except Exception:
        return "GENESIS"
    finally:
        conn.close()


def verify_audit_integrity():
    """Verify the hash-chain integrity of the audit log.

    Returns (is_valid, tampered_entries) where tampered_entries is a list
    of entry IDs where the chain breaks. An empty list means the chain
    is intact.
    """
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, user_id, action, details, created_at, prev_hash, entry_hash "
            "FROM audit_log ORDER BY id"
        ).fetchall()
    except Exception as e:
        return False, [{"error": str(e)}]
    finally:
        conn.close()

    tampered = []
    prev_hash = "GENESIS"
    for row in rows:
        payload = f"{prev_hash}|{row['user_id']}|{row['action']}|{row['details']}|{row['created_at']}"
        import hashlib
        expected = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
        if expected != row["entry_hash"] or row["prev_hash"] != prev_hash:
            tampered.append({
                "id": row["id"],
                "action": row["action"],
                "created_at": row["created_at"],
                "expected_hash": expected,
                "actual_hash": row["entry_hash"],
            })
        prev_hash = row["entry_hash"]
    return len(tampered) == 0, tampered


# ─── Auth decorators ────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        # 2FA gate: if 2FA enabled and not verified this session
        if session.get("totp_enabled") and not session.get("totp_verified"):
            if request.path.startswith("/api/") and not request.path.startswith("/api/2fa"):
                return jsonify({"error": "2FA required", "need_2fa": True}), 403
            if request.endpoint not in ("verify_2fa", "logout", "api_2fa_verify"):
                return redirect(url_for("verify_2fa"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated


# ─── Auth routes ────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if "user_id" in session and (not session.get("totp_enabled") or session.get("totp_verified")):
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        audit(None, "LOGIN_FAIL", username)
        if request.is_json:
            return jsonify({"error": "Invalid username or password"}), 401
        flash("Invalid username or password", "error")
        return render_template("login.html")

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["display_name"] = user["display_name"]
    session["role"] = user["role"]
    session["totp_enabled"] = bool(user["totp_enabled"])
    session["totp_verified"] = False

    audit(user["id"], "LOGIN_OK")

    if user["totp_enabled"]:
        if request.is_json:
            return jsonify({"ok": True, "need_2fa": True})
        return redirect(url_for("verify_2fa"))

    session["totp_verified"] = True
    if request.is_json:
        return jsonify({
            "ok": True,
            "need_2fa": False,
            "user": {
                "username": user["username"],
                "displayName": user["display_name"],
                "role": user["role"],
            },
        })
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or username).strip()
    confirm = data.get("confirm") or ""

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        conn.close()
        return jsonify({"error": "Username already taken"}), 400

    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn.execute(
        "INSERT INTO users (username, password_hash, display_name, role) VALUES (?,?,?,?)",
        (username, h, display_name, "analyst"),
    )
    conn.commit()
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    audit(uid, "REGISTER")

    return jsonify({"ok": True, "message": "Account created. Please login."})


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot.html")

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip().lower()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        conn.close()
        # Don't reveal existence
        return jsonify({"ok": True, "message": "If the account exists, a reset token was generated."})

    token = secrets.token_urlsafe(24)
    expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    conn.execute(
        "UPDATE users SET reset_token=?, reset_expires=? WHERE id=?",
        (token, expires, user["id"]),
    )
    conn.commit()
    conn.close()
    audit(user["id"], "RESET_TOKEN_GEN")

    # Local demo: return token (in production this would be emailed)
    return jsonify({
        "ok": True,
        "message": "Reset token generated (demo mode — no email).",
        "demo_token": token,
        "hint": "Use this token on the reset page. Valid for 1 hour.",
    })


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("reset.html")

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip().lower()
    token = (data.get("token") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND reset_token=?", (username, token)
    ).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Invalid username or token"}), 400

    expires = user["reset_expires"]
    if not expires or datetime.fromisoformat(expires) < datetime.utcnow():
        conn.close()
        return jsonify({"error": "Token expired"}), 400

    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn.execute(
        "UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?",
        (h, user["id"]),
    )
    conn.commit()
    conn.close()
    audit(user["id"], "PASSWORD_RESET")
    return jsonify({"ok": True, "message": "Password updated. Please login."})


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    session.clear()
    audit(uid, "LOGOUT")
    return redirect(url_for("login"))


# ─── 2FA routes ─────────────────────────────────────
@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if request.method == "GET":
        # Generate secret if not present
        secret = user["totp_secret"]
        if not secret:
            secret = pyotp.random_base32()
            conn.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user["id"]))
            conn.commit()
        conn.close()

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user["username"], issuer_name="LabTrace LogLens")

        # QR code as base64
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return render_template(
            "setup_2fa.html",
            secret=secret,
            qr_b64=qr_b64,
            enabled=bool(user["totp_enabled"]),
        )

    # POST: verify and enable
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or "").strip()
    secret = user["totp_secret"]
    if not secret:
        conn.close()
        return jsonify({"error": "No secret generated. Reload page."}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        conn.close()
        return jsonify({"error": "Invalid 2FA code"}), 400

    conn.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
    conn.commit()
    conn.close()
    session["totp_enabled"] = True
    session["totp_verified"] = True
    audit(user["id"], "2FA_ENABLED")
    return jsonify({"ok": True, "message": "2FA enabled successfully"})


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        conn.close()
        return jsonify({"error": "Wrong password"}), 400

    if user["totp_enabled"] and user["totp_secret"]:
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(code, valid_window=1):
            conn.close()
            return jsonify({"error": "Invalid 2FA code"}), 400

    conn.execute(
        "UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", (user["id"],)
    )
    conn.commit()
    conn.close()
    session["totp_enabled"] = False
    session["totp_verified"] = True
    audit(user["id"], "2FA_DISABLED")
    return jsonify({"ok": True})


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("totp_verified"):
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("verify_2fa.html")

    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or "").strip()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()

    if not user or not user["totp_secret"]:
        return jsonify({"error": "2FA not configured"}), 400

    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(code, valid_window=1):
        audit(user["id"], "2FA_FAIL")
        return jsonify({"error": "Invalid 2FA code"}), 401

    session["totp_verified"] = True
    audit(user["id"], "2FA_OK")
    return jsonify({"ok": True})


@app.route("/api/2fa/verify", methods=["POST"])
def api_2fa_verify():
    return verify_2fa()


# ─── Pages ──────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session and (not session.get("totp_enabled") or session.get("totp_verified")):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        user={
            "username": session.get("username"),
            "display_name": session.get("display_name"),
            "role": session.get("role"),
            "totp_enabled": session.get("totp_enabled", False),
        },
    )


# ─── API ────────────────────────────────────────────
@app.route("/api/me")
@login_required
def api_me():
    return jsonify({
        "username": session.get("username"),
        "displayName": session.get("display_name"),
        "role": session.get("role"),
        "totpEnabled": session.get("totp_enabled", False),
    })


@app.route("/api/settings", methods=["GET", "PUT"])
@login_required
def api_settings():
    conn = get_db()
    if request.method == "GET":
        s = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        conn.close()
        return jsonify(dict(s) if s else {})
    data = request.get_json() or {}
    conn.execute(
        """UPDATE settings SET
           open_time = COALESCE(?, open_time),
           close_time = COALESCE(?, close_time),
           n_threshold = COALESCE(?, n_threshold),
           w_minutes = COALESCE(?, w_minutes),
           r4_window = COALESCE(?, r4_window),
           r5_threshold = COALESCE(?, r5_threshold),
           r5_window = COALESCE(?, r5_window),
           r6_threshold = COALESCE(?, r6_threshold),
           r6_hours = COALESCE(?, r6_hours)
           WHERE id=1""",
        (
            data.get("open_time"),
            data.get("close_time"),
            data.get("n_threshold"),
            data.get("w_minutes"),
            data.get("r4_window"),
            data.get("r5_threshold"),
            data.get("r5_window"),
            data.get("r6_threshold"),
            data.get("r6_hours"),
        ),
    )
    conn.commit()
    conn.close()
    audit(session["user_id"], "SETTINGS_UPDATE", str(data))
    return jsonify({"ok": True})


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    rule_filter = (request.args.get("rule") or "").strip().upper()
    conn = get_db()
    events = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
    cases_count = conn.execute("SELECT COUNT(*) as c FROM cases").fetchone()["c"]
    open_cases = conn.execute(
        "SELECT COUNT(*) as c FROM cases WHERE status='open'"
    ).fetchone()["c"]
    high_priority = conn.execute(
        "SELECT COUNT(*) as c FROM cases "
        "WHERE status='open' AND priority='PRIORITY'"
    ).fetchone()["c"]
    to_review = conn.execute(
        "SELECT COUNT(*) as c FROM cases WHERE priority IN ('PRIORITY','REVIEW') AND status='open'"
    ).fetchone()["c"]
    routine = conn.execute(
        "SELECT COUNT(*) as c FROM cases WHERE priority='ROUTINE'"
    ).fetchone()["c"]
    # recent events (last 60 minutes, from the live raw_logs feed)
    recent_cutoff = (datetime.now() - timedelta(minutes=60)).strftime(TS_FMT)
    recent_events = conn.execute(
        "SELECT COUNT(*) as c FROM raw_logs WHERE timestamp >= ?",
        (recent_cutoff,),
    ).fetchone()["c"]
    new_alerts = conn.execute(
        "SELECT COUNT(*) as c FROM cases "
        "WHERE is_new=1 AND status='open' AND priority IN ('PRIORITY','REVIEW')"
    ).fetchone()["c"]
    cases = conn.execute(
        """SELECT id, case_key, account, computer, department, priority,
                  severity, score, r1, r2, r3, r4, r5, r6,
                  reason, human_check, event_count, status,
                  matched_event_ids, rules, rule_details,
                  r1_detail, r2_detail, r3_detail, r4_detail,
                  r5_detail, r6_detail, created_at, updated_at
           FROM cases
           ORDER BY CASE priority WHEN 'PRIORITY' THEN 0 WHEN 'REVIEW' THEN 1 ELSE 2 END, id"""
    ).fetchall()
    conn.close()

    case_list = []
    for c in cases:
        d = dict(c)
        rules = [r.strip() for r in (d.get("rules") or "").split(",") if r.strip()]
        # fallback: derive from boolean flags for legacy rows
        if not rules:
            rules = [r for r, flag in (
                ("R1", d.get("r1")), ("R2", d.get("r2")),
                ("R3", d.get("r3")), ("R4", d.get("r4")),
                ("R5", d.get("r5")), ("R6", d.get("r6"))) if flag]
        d["rules"] = rules
        # backfill severity / score for legacy rows
        if not d.get("severity"):
            d["severity"] = {"PRIORITY": "High",
                             "REVIEW": "Medium"}.get(
                                 d.get("priority"), "Low")
        if d.get("score") is None:
            d["score"] = 0
        # booleans for the UI
        for flag in ("r1", "r2", "r3", "r4", "r5", "r6"):
            d[flag] = bool(d.get(flag))
        # optional server-side rule filter (All when empty)
        if rule_filter and rule_filter not in rules:
            continue
        case_list.append(d)

    return jsonify({
        "metrics": {
            "events": events,
            "cases": cases_count,
            "openCases": open_cases,
            "highPriority": high_priority,
            "toReview": to_review,
            "routine": routine,
            "recentEvents": recent_events,
        },
        "newAlerts": new_alerts,
        "cases": case_list,
    })


@app.route("/api/cases/<int:case_id>")
@login_required
def api_case(case_id):
    conn = get_db()
    c = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not c:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    case = dict(c)
    # attach events
    matched = json.loads(case.get("matched_event_ids") or "[]")
    # R4 spans several computers, R5 several accounts — fetch the
    # actual matched events rather than a single account@computer.
    if matched:
        placeholders = ",".join("?" for _ in matched)
        if case.get("r4"):
            rows = conn.execute(
                f"SELECT event_id, timestamp, account, computer, event, "
                f"department_case FROM events "
                f"WHERE event_id IN ({placeholders}) AND account=? "
                f"ORDER BY timestamp",
                (*matched, case["account"]),
            ).fetchall()
        elif case.get("r5"):
            rows = conn.execute(
                f"SELECT event_id, timestamp, account, computer, event, "
                f"department_case FROM events "
                f"WHERE event_id IN ({placeholders}) AND computer=? "
                f"ORDER BY timestamp",
                (*matched, case["computer"]),
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT event_id, timestamp, account, computer, event, "
                f"department_case FROM events "
                f"WHERE event_id IN ({placeholders}) "
                f"ORDER BY timestamp",
                matched,
            ).fetchall()
        if not rows:
            # fall back to the account+computer window
            rows = conn.execute(
                "SELECT event_id, timestamp, account, computer, event, "
                "department_case FROM events WHERE account=? AND computer=? "
                "ORDER BY timestamp",
                (case["account"], case["computer"]),
            ).fetchall()
    else:
        rows = conn.execute(
            "SELECT event_id, timestamp, account, computer, event, "
                "department_case FROM events WHERE account=? AND computer=? "
                "ORDER BY timestamp",
            (case["account"], case["computer"]),
        ).fetchall()
    case["events"] = [dict(e) for e in rows]
    case["matched_event_ids"] = matched
    for key in ("r1_detail", "r2_detail", "r3_detail",
                "r4_detail", "r5_detail", "r6_detail",
                "rule_details"):
        try:
            case[key] = json.loads(case.get(key) or "[]"
                                   if key == "rule_details"
                                   else case.get(key) or "{}")
        except Exception:
            case[key] = [] if key == "rule_details" else {}
    # boolean flags as real booleans for the UI
    for flag in ("r1", "r2", "r3", "r4", "r5", "r6"):
        case[flag] = bool(case.get(flag))
    rules = [r.strip() for r in (case.get("rules") or "").split(",")
             if r.strip()]
    if not rules:
        rules = [r for r, flag in (
            ("R1", case.get("r1")), ("R2", case.get("r2")),
            ("R3", case.get("r3")), ("R4", case.get("r4")),
            ("R5", case.get("r5")), ("R6", case.get("r6"))) if flag]
    case["rules"] = rules
    # safety net: a case written by an older engine has the
    # rule flags but no stored rule_details — synthesise a
    # minimal explainable view from the stored rN_detail so
    # the Evidence Panel is never blank. The scheduler
    # backfills the full detail on its next pass.
    if not case["rule_details"] and rules:
        case["rule_details"] = [
            {
                "id": r,
                "name": RULE_NAMES.get(r, r),
                "severity": RULE_SEVERITY.get(r, "Medium"),
                "triggered": True,
                "explanation": RULE_NAMES.get(r, r) +
                              " — refreshing explanation…",
                "recommendation": RULE_RECOMMENDATIONS.get(r, ""),
                "threshold": "",
                "window": "",
                "matchedEventIds": case.get("matched_event_ids") or [],
                "detail": case.get(r.lower() + "_detail") or {},
            }
            for r in rules
        ]
    conn.close()
    return jsonify(case)


@app.route("/api/cases/<int:case_id>/action", methods=["POST"])
@login_required
def api_case_action(case_id):
    data = request.get_json() or {}
    action = (data.get("action") or "").lower()
    if action not in ("confirm", "dismiss", "escalate"):
        return jsonify({"error": "action must be confirm, dismiss or escalate"}), 400
    conn = get_db()
    if action == "escalate":
        # Escalation: raise the case priority to PRIORITY and
        # reopen it for review. Recorded in the audit log. No host
        # is blocked and no session is terminated.
        conn.execute(
            "UPDATE cases SET priority='PRIORITY', severity='High', "
            "status='open', is_new=1 WHERE id=?", (case_id,)
        )
        conn.commit()
        conn.close()
        audit(session["user_id"], "CASE_ESCALATE", f"case_id={case_id}")
        return jsonify({"ok": True, "status": "open",
                        "priority": "PRIORITY"})
    status = "confirmed" if action == "confirm" else "dismissed"
    conn.execute(
        "UPDATE cases SET status=?, is_new=0 WHERE id=?", (status, case_id)
    )
    conn.commit()
    conn.close()
    audit(session["user_id"], f"CASE_{action.upper()}", f"case_id={case_id}")
    return jsonify({"ok": True, "status": status})


def _save_and_detect(events):
    conn = get_db()
    conn.execute("DELETE FROM events")
    # only manual-origin cases are replaced by an upload/replay —
    # live-detected cases (origin='live') are preserved
    conn.execute("DELETE FROM cases WHERE COALESCE(origin,'manual')='manual'")
    for e in events:
        conn.execute(
            """INSERT INTO events (event_id, timestamp, account, computer, event, department_case)
               VALUES (?,?,?,?,?,?)""",
            (
                str(e.get("event_id", "")),
                str(e.get("timestamp", "")),
                str(e.get("account", "")),
                str(e.get("computer", "")),
                str(e.get("event", "")),
                str(e.get("department_case", "")),
            ),
        )
    s = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
    N = s["n_threshold"]
    W = s["w_minutes"]
    open_t = s["open_time"]
    close_t = s["close_time"]
    r4_window = s["r4_window"] if s["r4_window"] is not None else 10
    r5_threshold = (s["r5_threshold"]
                      if s["r5_threshold"] is not None else 4)
    r5_window = s["r5_window"] if s["r5_window"] is not None else 10
    r6_threshold = (s["r6_threshold"]
                      if s["r6_threshold"] is not None else 2)
    r6_hours = s["r6_hours"] if s["r6_hours"] is not None else 24
    prior_matches = get_prior_matches()
    cases = detect_cases(
        events, N=N, W=W, open_time=open_t, close_time=close_t,
        r4_window=r4_window, r5_threshold=r5_threshold,
        r5_window=r5_window, r6_threshold=r6_threshold,
        r6_hours=r6_hours, prior_matches=prior_matches,
    )
    now = datetime.now().strftime(TS_FMT)
    for c in cases:
        # replace any existing row with the same key (manual upload wins)
        conn.execute("DELETE FROM cases WHERE case_key=?", (c["case_key"],))
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
                c["case_key"],
                c["account"],
                c["computer"],
                c["department"],
                c["priority"],
                c.get("severity", "Low"),
                c.get("score", 0),
                1 if c["r1"] else 0,
                1 if c["r2"] else 0,
                1 if c["r3"] else 0,
                1 if c["r4"] else 0,
                1 if c["r5"] else 0,
                1 if c["r6"] else 0,
                c["reason"],
                c.get("human_check"),
                c["event_count"],
                json.dumps(c.get("matched_event_ids", [])),
                json.dumps(c.get("r1_detail") or {}),
                json.dumps(c.get("r2_detail") or {}),
                json.dumps(c.get("r3_detail") or {}),
                json.dumps(c.get("r4_detail") or {}),
                json.dumps(c.get("r5_detail") or {}),
                json.dumps(c.get("r6_detail") or {}),
                ",".join(c.get("rules") or []),
                json.dumps(c.get("rule_details") or []),
                c.get("status", "open"),
                now, now, "manual", 1,
            ),
        )
        # record the occurrence so R6 works across manual replays too
        _record_match(conn, c, "manual")
    conn.commit()
    n_events = len(events)
    n_cases = len(cases)
    conn.close()
    return n_events, n_cases


@app.route("/api/load-demo", methods=["POST"])
@login_required
def api_load_demo():
    events = []
    with open(SAMPLE_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            e = {
                "event_id": row.get("event_id", ""),
                "timestamp": row.get("timestamp", ""),
                "account": row.get("account", ""),
                "computer": row.get("computer", ""),
                "event": row.get("event", ""),
                "department_case": row.get("department_case", ""),
            }
            e["event"] = "Failure" if e["event"].strip().lower() == "failure" else "Success"
            events.append(e)
    n_events, n_cases = _save_and_detect(events)
    audit(session["user_id"], "LOAD_DEMO", f"events={n_events} cases={n_cases}")
    return jsonify({"ok": True, "events": n_events, "cases": n_cases})


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only CSV allowed"}), 400
    try:
        content = f.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        events = []
        for row in reader:
            e = {
                "event_id": row.get("event_id", row.get("EventId", "")),
                "timestamp": row.get("timestamp", row.get("Timestamp", "")),
                "account": row.get("account", row.get("Account", "")),
                "computer": row.get("computer", row.get("Computer", "")),
                "event": row.get("event", row.get("Event", "")),
                "department_case": row.get("department_case", row.get("Department", "")),
            }
            e["event"] = "Failure" if str(e["event"]).strip().lower() == "failure" else "Success"
            events.append(e)
        if not events:
            return jsonify({"error": "No valid events found"}), 400
        n_events, n_cases = _save_and_detect(events)
        audit(session["user_id"], "CSV_UPLOAD", f"events={n_events} cases={n_cases}")
        return jsonify({"ok": True, "events": n_events, "cases": n_cases})
    except Exception as ex:
        return jsonify({"error": str(ex)}), 400


@app.route("/api/replay", methods=["POST"])
@login_required
def api_replay():
    data = request.get_json() or {}
    conn = get_db()
    if data:
        conn.execute(
            """UPDATE settings SET
               n_threshold = COALESCE(?, n_threshold),
               w_minutes = COALESCE(?, w_minutes),
               open_time = COALESCE(?, open_time),
               close_time = COALESCE(?, close_time)
               WHERE id=1""",
            (
                data.get("n_threshold"),
                data.get("w_minutes"),
                data.get("open_time"),
                data.get("close_time"),
            ),
        )
        conn.commit()
    s = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
    rows = conn.execute(
        "SELECT event_id, timestamp, account, computer, event, department_case FROM events ORDER BY timestamp"
    ).fetchall()
    conn.close()
    if not rows:
        return jsonify({"error": "No events loaded. Use Load Demo or Upload CSV first."}), 400
    events = [dict(r) for r in rows]
    n_events, n_cases = _save_and_detect(events)
    audit(session["user_id"], "REPLAY", f"N={s['n_threshold']} W={s['w_minutes']}")
    return jsonify({
        "ok": True,
        "cases": n_cases,
        "settings": dict(s),
    })


@app.route("/api/audit")
@login_required
def api_audit():
    conn = get_db()
    rows = conn.execute(
        """SELECT a.id, a.action, a.details, a.created_at, u.username
           FROM audit_log a LEFT JOIN users u ON a.user_id = u.id
           ORDER BY a.id DESC LIMIT 100"""
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/audit/verify")
@login_required
def api_audit_verify():
    """Verify the hash-chain integrity of the audit log."""
    is_valid, tampered = verify_audit_integrity()
    if is_valid:
        return jsonify({"valid": True, "message": "Audit log integrity verified"})
    return jsonify({
        "valid": False,
        "message": "Audit log integrity check FAILED",
        "tampered_entries": tampered,
    }), 400


@app.route("/api/mode")
@login_required
def api_mode():
    """Return the current monitoring mode and event source status.

    Live Mode: genuine Windows Security Log events are being collected.
    Demo Mode: only simulated/uploaded events exist (no live collection).
    """
    conn = get_db()
    # Check if any live Windows events exist
    live_windows = conn.execute(
        "SELECT COUNT(*) c FROM raw_logs WHERE source='windows'"
    ).fetchone()["c"]
    live_total = conn.execute(
        "SELECT COUNT(*) c FROM raw_logs"
    ).fetchone()["c"]
    manual_total = conn.execute(
        "SELECT COUNT(*) c FROM events"
    ).fetchone()["c"]
    conn.close()

    # Determine mode: if we have live Windows events, we're in Live Mode
    is_live = live_windows > 0
    # Check collector status
    collectors = MANAGER.status()
    windows_collector = next(
        (c for c in collectors if c["key"] == "windows"), None
    )
    collector_healthy = (
        windows_collector and windows_collector["status"] == "active"
    )

    return jsonify({
        "mode": "live" if is_live else "demo",
        "isLive": is_live,
        "liveWindowsEvents": live_windows,
        "totalLiveEvents": live_total,
        "manualEvents": manual_total,
        "collectorHealthy": collector_healthy,
        "collectorStatus": windows_collector["status"] if windows_collector else "unknown",
        "eventSource": "windows_security_log" if is_live else "manual_upload",
    })


# ─── Live Monitor ─────────────────────────────────────
@app.route("/monitor")
@login_required
def monitor():
    return render_template(
        "monitor.html",
        user={
            "username": session.get("username"),
            "display_name": session.get("display_name"),
            "role": session.get("role"),
            "totp_enabled": session.get("totp_enabled", False),
        },
    )


# ─── Live Monitor time helpers ───────────────────────────────
# Every raw_logs.timestamp is stored in LOCAL time as
# 'YYYY-MM-DD HH:MM:SS' (see app/collector.py) and compared with
# datetime.now() (also local). All monitor endpoints therefore share the
# same timezone and bucket grid, so the charts, labels and KPIs agree.
MONITOR_WINDOWS = {
    # endpoint  → (bucket_seconds, span_seconds)
    "events":  (300, 2 * 60 * 60),   # 5-minute buckets, last 2 h
    "sources": (600, 6 * 60 * 60),   # 10-minute buckets, last 6 h
    "total":   (3600, 24 * 60 * 60),  # hourly buckets, last 24 h
}


def _bucket_grid(bucket_seconds, span_seconds, now=None):
    """Fixed, wall-clock-aligned bucket grid for a monitor chart.

    Bucket i covers [start + i*bucket, start + (i+1)*bucket). The grid is
    aligned to round *local* wall-clock marks (e.g. :00/:05 for 5-minute
    buckets) — computed from local time components, not epoch seconds, so
    alignment holds even in timezones whose offset is not a whole hour.
    It always contains exactly span/bucket buckets, so labels never drift
    between refreshes and missing periods are returned as zero counts.
    """
    now = now or datetime.now()
    n = max(1, int(span_seconds // bucket_seconds))
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end_secs = now.hour * 3600 + now.minute * 60 + now.second
    end_secs = (end_secs // bucket_seconds) * bucket_seconds
    start_secs = end_secs - (n - 1) * bucket_seconds
    start = midnight + timedelta(seconds=start_secs)
    labels = [
        (start + timedelta(seconds=i * bucket_seconds)).strftime("%H:%M")
        for i in range(n)
    ]
    return start, labels, n


def _bucket_index(ts, start_epoch, bucket_seconds, n):
    """Bucket index for a stored timestamp, or None if outside the grid."""
    dt = parse_ts(ts)
    if not dt:
        return None
    idx = int((dt.timestamp() - start_epoch) // bucket_seconds)
    if 0 <= idx < n:
        return idx
    return None


def _raw_rows_since(cutoff_dt):
    cutoff_str = cutoff_dt.strftime(TS_FMT)
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, source, event FROM raw_logs WHERE timestamp >= ?",
        (cutoff_str,),
    ).fetchall()
    conn.close()
    return rows


def _bucket_counts(rows, start, bucket_seconds, n):
    """Count raw rows into a fixed bucket grid (zero-filled)."""
    start_epoch = int(start.timestamp())
    counts = [0] * n
    for r in rows:
        idx = _bucket_index(r["timestamp"], start_epoch, bucket_seconds, n)
        if idx is not None:
            counts[idx] += 1
    return counts


@app.route("/api/monitor/overview")
@login_required
def api_monitor_overview():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) c FROM raw_logs").fetchone()["c"]
    sources = conn.execute(
        "SELECT source, COUNT(*) c FROM raw_logs "
        "GROUP BY source ORDER BY c DESC"
    ).fetchall()
    minute_ago = (datetime.now() - timedelta(minutes=1)).strftime(TS_FMT)
    last_min = conn.execute(
        "SELECT COUNT(*) c FROM raw_logs WHERE timestamp >= ?", (minute_ago,)
    ).fetchone()["c"]
    open_cases = conn.execute(
        "SELECT COUNT(*) c FROM cases WHERE status='open'"
    ).fetchone()["c"]
    priority_open = conn.execute(
        "SELECT COUNT(*) c FROM cases WHERE status='open' AND priority='PRIORITY'"
    ).fetchone()["c"]
    review_open = conn.execute(
        "SELECT COUNT(*) c FROM cases WHERE status='open' AND priority='REVIEW'"
    ).fetchone()["c"]
    conn.close()
    # Events/sec = real arrival rate measured over a documented window
    # (collector ring buffer). It falls back to 0 when nothing arrives.
    eps = MANAGER.eps_stats()["eps"]
    return jsonify({
        "totalLogs": total,
        "eventsLastMinute": last_min,
        "eventsPerSecond": eps,
        "epsWindowSeconds": EPS_WINDOW_SECONDS,
        "sources": [{"source": r["source"], "count": r["c"]} for r in sources],
        "cases": {"open": open_cases, "priority": priority_open,
                  "review": review_open},
    })


@app.route("/api/monitor/events-timeline")
@login_required
def api_monitor_events_timeline():
    """Events per 5 minutes, wall-clock aligned, zero-filled.

    The window dynamically covers the actual data range: if logs exist
    outside the default 2 h span, the grid extends to include them
    (capped at 24 h). This ensures the chart always reflects the real
    event distribution instead of showing all zeros.
    """
    bucket, span = MONITOR_WINDOWS["events"]
    conn = get_db()
    row = conn.execute(
        "SELECT MIN(timestamp) mn, MAX(timestamp) mx FROM raw_logs"
    ).fetchone()
    conn.close()
    now = datetime.now()
    start = now - timedelta(seconds=span)
    end = now
    if row and row["mn"] and row["mx"]:
        mn = parse_ts(row["mn"])
        mx = parse_ts(row["mx"])
        if mn and mx:
            if mn < start:
                start = mn.replace(second=0, microsecond=0)
                start -= timedelta(seconds=(start.second % bucket))
                start -= timedelta(seconds=bucket)
            if mx > end:
                end = mx
    start_epoch = int(start.timestamp())
    end_epoch = int(end.timestamp())
    n = max(1, (end_epoch - start_epoch) // bucket + 1)
    n = min(n, 288)
    labels = [
        (start + timedelta(seconds=i * bucket)).strftime("%H:%M")
        for i in range(n)
    ]
    rows = _raw_rows_since(start)
    counts = _bucket_counts(rows, start, bucket, n)
    return jsonify({
        "labels": labels, "counts": counts,
        "bucketSeconds": bucket, "spanSeconds": span,
    })


@app.route("/api/monitor/sources-timeline")
@login_required
def api_monitor_sources_timeline():
    """Logs per source over time (10-minute buckets, last 6 h or anchored to data)."""
    bucket, span = MONITOR_WINDOWS["sources"]
    conn = get_db()
    row = conn.execute("SELECT MIN(timestamp) mn, MAX(timestamp) mx FROM raw_logs").fetchone()
    all_sources = [r["source"] for r in conn.execute("SELECT DISTINCT source FROM raw_logs").fetchall() if r["source"]]
    conn.close()

    now = datetime.now()
    start = now - timedelta(seconds=span)
    if row and row["mx"]:
        mx = parse_ts(row["mx"])
        if mx and (now - mx).total_seconds() > span:
            start = mx - timedelta(seconds=span)

    start_epoch = int(start.timestamp())
    n = max(1, int(span // bucket))
    labels = [
        (start + timedelta(seconds=i * bucket)).strftime("%H:%M")
        for i in range(n)
    ]
    rows = _raw_rows_since(start)
    series = {}
    for src in all_sources:
        series[src] = [0] * n

    for r in rows:
        idx = _bucket_index(r["timestamp"], start_epoch, bucket, n)
        if idx is None:
            continue
        src = r["source"] or "unknown"
        if src not in series:
            series[src] = [0] * n
        series[src][idx] += 1

    ordered = dict(sorted(series.items(),
                          key=lambda kv: (-sum(kv[1]), kv[0])))
    return jsonify({
        "labels": labels, "series": ordered,
        "bucketSeconds": bucket, "spanSeconds": span,
    })


@app.route("/api/monitor/total-timeline")
@login_required
def api_monitor_total_timeline():
    """Total logs timeline — hourly buckets over the last 24 h or anchored to data."""
    bucket, span = MONITOR_WINDOWS["total"]
    conn = get_db()
    row = conn.execute("SELECT MIN(timestamp) mn, MAX(timestamp) mx FROM raw_logs").fetchone()
    conn.close()

    now = datetime.now()
    start = now - timedelta(seconds=span)
    if row and row["mx"]:
        mx = parse_ts(row["mx"])
        if mx and (now - mx).total_seconds() > span:
            start = mx - timedelta(seconds=span)

    n = max(1, int(span // bucket))
    labels = [
        (start + timedelta(seconds=i * bucket)).strftime("%H:%M")
        for i in range(n)
    ]
    rows = _raw_rows_since(start)
    counts = _bucket_counts(rows, start, bucket, n)
    return jsonify({
        "labels": labels, "counts": counts,
        "bucketSeconds": bucket, "spanSeconds": span,
    })


@app.route("/api/monitor/collectors")
@login_required
def api_monitor_collectors():
    return jsonify({"collectors": MANAGER.status()})


@app.route("/api/monitor/server")
@login_required
def api_monitor_server():
    return jsonify(MANAGER.server())


@app.route("/api/monitor/syslog-stats")
@login_required
def api_monitor_syslog_stats():
    eps = MANAGER.eps_stats()
    day_ago = (datetime.now() - timedelta(hours=24)).strftime(TS_FMT)
    conn = get_db()
    donut = conn.execute(
        "SELECT severity, COUNT(*) c FROM raw_logs WHERE timestamp >= ? "
        "GROUP BY severity ORDER BY c DESC", (day_ago,)
    ).fetchall()
    udp_24h = conn.execute(
        "SELECT COUNT(*) c FROM raw_logs WHERE source='syslog_udp' "
        "AND timestamp >= ?", (day_ago,)
    ).fetchone()["c"]
    conn.close()
    return jsonify({
        "eps": eps["eps"],
        "maxEps": eps["maxEps"],
        "avgEps": eps["avgEps"],
        "syslogLast24h": udp_24h,
        "donut": [{"label": r["severity"], "count": r["c"]} for r in donut],
    })


@app.route("/api/monitor/alerts")
@login_required
def api_monitor_alerts():
    """Latest alerts (PRIORITY/REVIEW first) for the Live Monitor table."""
    conn = get_db()
    rows = conn.execute(
        """SELECT id, case_key, account, computer, priority, reason, status,
                  updated_at, created_at, origin, is_new
           FROM cases
           WHERE priority IN ('PRIORITY','REVIEW')
           ORDER BY CASE priority WHEN 'PRIORITY' THEN 0 ELSE 1 END,
                    COALESCE(updated_at, created_at, id) DESC
           LIMIT 15"""
    ).fetchall()
    conn.close()
    return jsonify({"alerts": [dict(r) for r in rows]})


@app.route("/api/monitor/banner")
@login_required
def api_monitor_banner():
    conn = get_db()
    rows = conn.execute(
        """SELECT id, case_key, priority, reason, updated_at
           FROM cases
           WHERE is_new=1 AND status='open' AND priority IN ('PRIORITY','REVIEW')
           ORDER BY COALESCE(updated_at, id) DESC LIMIT 10"""
    ).fetchall()
    conn.close()
    cases = [dict(r) for r in rows]
    return jsonify({"show": bool(cases), "count": len(cases), "cases": cases})


@app.route("/api/monitor/banner/ack", methods=["POST"])
@login_required
def api_monitor_banner_ack():
    conn = get_db()
    conn.execute("UPDATE cases SET is_new=0 WHERE is_new=1")
    conn.commit()
    conn.close()
    audit(session["user_id"], "BANNER_ACK")
    return jsonify({"ok": True})


# Init DB on startup
init_db()
