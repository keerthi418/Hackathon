"""Verify safe migration on a copy of the real database."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import sqlite3

import app.config
import app.main
import app.scheduler
import app.collector

SRC = "data/labtrace.db"
TMP = "data/_migration_test.db"

shutil.copy(SRC, TMP)
app.config.DB_PATH = TMP
app.main.DB_PATH = TMP
app.scheduler.DB_PATH = TMP
app.collector.DB_PATH = TMP


def snapshot():
    conn = sqlite3.connect(TMP)
    d = {
        "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "cases": conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
        "audit": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        "raw_logs": conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0],
        "case_cols": [r[1] for r in conn.execute("PRAGMA table_info(cases)")],
        "settings_cols": [r[1] for r in conn.execute("PRAGMA table_info(settings)")],
        "rule_matches": bool(conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='rule_matches'").fetchone()),
    }
    conn.close()
    return d


before = snapshot()
print("BEFORE:", before["users"], "users,", before["cases"],
      "cases,", before["audit"], "audit,", before["raw_logs"], "raw_logs")
print("BEFORE case cols:", before["case_cols"])

app.main.init_db()

after = snapshot()
print("AFTER:", after["users"], "users,", after["cases"],
      "cases,", after["audit"], "audit,", after["raw_logs"], "raw_logs")
print("AFTER case cols:", after["case_cols"])
print("settings cols:", after["settings_cols"])
print("rule_matches table:", after["rule_matches"])

preserved = (before["users"] == after["users"]
             and before["cases"] == after["cases"]
             and before["audit"] == after["audit"]
             and before["raw_logs"] == after["raw_logs"])
print("DATA PRESERVED:", preserved)

new_cols = ["r3", "r4", "r5", "r6", "r3_detail", "r4_detail",
            "r5_detail", "r6_detail", "rules", "rule_details",
            "severity", "score"]
print("NEW COLUMNS PRESENT:", all(c in after["case_cols"] for c in new_cols))

os.unlink(TMP)
print("OK")
