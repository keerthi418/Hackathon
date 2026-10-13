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
from app.engine import detect_cases, parse_ts
from app.collector import MANAGER, ensure_schema
from app.scheduler import migrate_cases_table

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
            w_minutes INTEGER DEFAULT 5
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
            r1 INTEGER,
            r2 INTEGER,
            reason TEXT,
            human_check TEXT,
            event_count INTEGER,
            matched_event_ids TEXT,
            r1_detail TEXT,
            r2_detail TEXT,
            status TEXT DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now'))
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
    ensure_schema()
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


def audit(user_id, action, details=""):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (user_id, action, details) VALUES (?,?,?)",
            (user_id, action, details),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


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
           w_minutes = COALESCE(?, w_minutes)
           WHERE id=1""",
        (
            data.get("open_time"),
            data.get("close_time"),
            data.get("n_threshold"),
            data.get("w_minutes"),
        ),
    )
    conn.commit()
    conn.close()
    audit(session["user_id"], "SETTINGS_UPDATE", str(data))
    return jsonify({"ok": True})


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    conn = get_db()
    events = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
    cases_count = conn.execute("SELECT COUNT(*) as c FROM cases").fetchone()["c"]
    to_review = conn.execute(
        "SELECT COUNT(*) as c FROM cases WHERE priority IN ('PRIORITY','REVIEW') AND status='open'"
    ).fetchone()["c"]
    routine = conn.execute(
        "SELECT COUNT(*) as c FROM cases WHERE priority='ROUTINE'"
    ).fetchone()["c"]
    new_alerts = conn.execute(
        "SELECT COUNT(*) as c FROM cases "
        "WHERE is_new=1 AND status='open' AND priority IN ('PRIORITY','REVIEW')"
    ).fetchone()["c"]
    cases = conn.execute(
        """SELECT id, case_key, account, computer, department, priority, r1, r2,
                  reason, human_check, event_count, status
           FROM cases
           ORDER BY CASE priority WHEN 'PRIORITY' THEN 0 WHEN 'REVIEW' THEN 1 ELSE 2 END, id"""
    ).fetchall()
    conn.close()
    return jsonify({
        "metrics": {
            "events": events,
            "cases": cases_count,
            "toReview": to_review,
            "routine": routine,
        },
        "newAlerts": new_alerts,
        "cases": [dict(c) for c in cases],
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
    events = conn.execute(
        "SELECT event_id, timestamp, account, computer, event, department_case FROM events WHERE account=? AND computer=? ORDER BY timestamp",
        (case["account"], case["computer"]),
    ).fetchall()
    case["events"] = [dict(e) for e in events]
    case["matched_event_ids"] = matched
    try:
        case["r1_detail"] = json.loads(case["r1_detail"] or "{}")
    except Exception:
        case["r1_detail"] = {}
    try:
        case["r2_detail"] = json.loads(case["r2_detail"] or "{}")
    except Exception:
        case["r2_detail"] = {}
    conn.close()
    return jsonify(case)


@app.route("/api/cases/<int:case_id>/action", methods=["POST"])
@login_required
def api_case_action(case_id):
    data = request.get_json() or {}
    action = (data.get("action") or "").lower()
    if action not in ("confirm", "dismiss"):
        return jsonify({"error": "action must be confirm or dismiss"}), 400
    status = "confirmed" if action == "confirm" else "dismissed"
    conn = get_db()
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
    cases = detect_cases(events, N=N, W=W, open_time=open_t, close_time=close_t)
    now = datetime.now().strftime(TS_FMT)
    for c in cases:
        # replace any existing row with the same key (manual upload wins)
        conn.execute("DELETE FROM cases WHERE case_key=?", (c["case_key"],))
        conn.execute(
            """INSERT INTO cases
               (case_key, account, computer, department, priority, r1, r2, reason,
                human_check, event_count, matched_event_ids, r1_detail, r2_detail,
                status, created_at, updated_at, origin, is_new)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                c["case_key"],
                c["account"],
                c["computer"],
                c["department"],
                c["priority"],
                1 if c["r1"] else 0,
                1 if c["r2"] else 0,
                c["reason"],
                c.get("human_check"),
                c["event_count"],
                json.dumps(c.get("matched_event_ids", [])),
                json.dumps(c.get("r1_detail") or {}),
                json.dumps(c.get("r2_detail") or {}),
                c.get("status", "open"),
                now, now, "manual", 1,
            ),
        )
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


def _raw_rows_since(cutoff_str):
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, source, event FROM raw_logs WHERE timestamp >= ?",
        (cutoff_str,),
    ).fetchall()
    conn.close()
    return rows


def _bucket_counts(rows, cutoff, bucket_seconds):
    """Bucket timestamps into fixed-width bins starting at cutoff."""
    now = datetime.now()
    n = max(1, int((now - cutoff).total_seconds() // bucket_seconds) + 1)
    counts = [0] * n
    labels = [
        (cutoff + timedelta(seconds=i * bucket_seconds)).strftime("%H:%M")
        for i in range(n)
    ]
    for r in rows:
        dt = parse_ts(r["timestamp"])
        if not dt or dt < cutoff:
            continue
        idx = int((dt - cutoff).total_seconds() // bucket_seconds)
        if 0 <= idx < n:
            counts[idx] += 1
    return labels, counts


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
    return jsonify({
        "totalLogs": total,
        "eventsLastMinute": last_min,
        "sources": [{"source": r["source"], "count": r["c"]} for r in sources],
        "cases": {"open": open_cases, "priority": priority_open,
                  "review": review_open},
    })


@app.route("/api/monitor/events-timeline")
@login_required
def api_monitor_events_timeline():
    """Events per 5 minutes (last 2 hours)."""
    cutoff = datetime.now() - timedelta(hours=2)
    rows = _raw_rows_since(cutoff.strftime(TS_FMT))
    labels, counts = _bucket_counts(rows, cutoff, 300)
    return jsonify({"labels": labels, "counts": counts})


@app.route("/api/monitor/sources-timeline")
@login_required
def api_monitor_sources_timeline():
    """Logs per source over time (10-minute buckets, last 6 hours)."""
    cutoff = datetime.now() - timedelta(hours=6)
    rows = _raw_rows_since(cutoff.strftime(TS_FMT))
    now = datetime.now()
    n = max(1, int((now - cutoff).total_seconds() // 600) + 1)
    labels = [
        (cutoff + timedelta(seconds=i * 600)).strftime("%H:%M") for i in range(n)
    ]
    series = {}
    for r in rows:
        dt = parse_ts(r["timestamp"])
        if not dt or dt < cutoff:
            continue
        idx = int((dt - cutoff).total_seconds() // 600)
        if 0 <= idx < n:
            series.setdefault(r["source"], [0] * n)
            series[r["source"]][idx] += 1
    return jsonify({"labels": labels, "series": series})


@app.route("/api/monitor/total-timeline")
@login_required
def api_monitor_total_timeline():
    """Total logs timeline — hourly buckets over the last 24 hours."""
    cutoff = datetime.now() - timedelta(hours=24)
    rows = _raw_rows_since(cutoff.strftime(TS_FMT))
    labels, counts = _bucket_counts(rows, cutoff, 3600)
    return jsonify({"labels": labels, "counts": counts})


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
