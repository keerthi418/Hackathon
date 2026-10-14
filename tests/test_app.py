"""Integration tests for the Flask app, API and scheduler.

These tests run against a temporary SQLite database so the real
data/labtrace.db is never touched.

Run from the project root:
    python -m unittest discover -s tests -t .
"""
import csv
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.config  # noqa: E402
import app.collector  # noqa: E402
import app.main  # noqa: E402
import app.scheduler  # noqa: E402


class AppTestCase(unittest.TestCase):
    """Base class that swaps in a temporary database."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.db_path = tmp.name
        # every module imported DB_PATH by value → patch each one
        self._patches = [
            mock.patch.object(app.config, "DB_PATH", self.db_path),
            mock.patch.object(app.main, "DB_PATH", self.db_path),
            mock.patch.object(app.scheduler, "DB_PATH", self.db_path),
            mock.patch.object(app.collector, "DB_PATH", self.db_path),
        ]
        for p in self._patches:
            p.start()
        app.main.init_db()
        self.app = app.main.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def login(self, username="admin", password="LabTrace@2025"):
        return self.client.post(
            "/login",
            data=json.dumps({"username": username, "password": password}),
            content_type="application/json",
        )

    def seed_settings(self, **overrides):
        conn = sqlite3.connect(self.db_path)
        defaults = {
            "open_time": "08:30", "close_time": "17:30",
            "n_threshold": 3, "w_minutes": 5,
            "r4_window": 10, "r5_threshold": 4, "r5_window": 10,
            "r6_threshold": 2, "r6_hours": 24,
        }
        defaults.update(overrides)
        assignments = ", ".join(f"{k} = ?" for k in defaults)
        conn.execute(
            f"UPDATE settings SET {assignments} WHERE id=1",
            list(defaults.values()),
        )
        conn.commit()
        conn.close()


class AuthTests(AppTestCase):
    def test_login_page_loads(self):
        res = self.client.get("/login")
        self.assertEqual(res.status_code, 200)

    def test_login_success_creates_session(self):
        res = self.login()
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["need_2fa"])

    def test_login_failure_rejected(self):
        res = self.login(password="wrong")
        self.assertEqual(res.status_code, 401)

    def test_dashboard_requires_login(self):
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 302)  # redirect to /login

    def test_api_requires_login(self):
        res = self.client.get("/api/dashboard")
        self.assertEqual(res.status_code, 401)

    def test_registration_and_login(self):
        res = self.client.post(
            "/register",
            data=json.dumps({
                "username": "newanalyst",
                "password": "LongPassword1",
                "confirm": "LongPassword1",
                "display_name": "New Analyst",
            }),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        res = self.login("newanalyst", "LongPassword1")
        self.assertEqual(res.status_code, 200)

    def test_settings_roundtrip(self):
        self.login()
        res = self.client.get("/api/settings")
        self.assertEqual(res.status_code, 200)
        s = res.get_json()
        self.assertEqual(s["open_time"], "08:30")
        # update the new R4–R6 thresholds
        res = self.client.put(
            "/api/settings",
            data=json.dumps({
                "r4_window": 15, "r5_threshold": 5,
                "r5_window": 12, "r6_threshold": 3, "r6_hours": 48,
            }),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        s = self.client.get("/api/settings").get_json()
        self.assertEqual(s["r4_window"], 15)
        self.assertEqual(s["r5_threshold"], 5)
        self.assertEqual(s["r5_window"], 12)
        self.assertEqual(s["r6_threshold"], 3)
        self.assertEqual(s["r6_hours"], 48)


class DashboardApiTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_dashboard_metrics_shape(self):
        res = self.client.get("/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("metrics", data)
        for key in ("events", "cases", "openCases", "highPriority",
                        "toReview", "routine", "recentEvents"):
            self.assertIn(key, data["metrics"])
        self.assertIn("cases", data)
        self.assertIn("newAlerts", data)

    def test_rule_filter_param(self):
        # load demo data, then filter server-side by rule
        self.client.post("/api/load-demo")
        all_cases = self.client.get("/api/dashboard").get_json()["cases"]
        r1_only = self.client.get(
            "/api/dashboard?rule=R1").get_json()["cases"]
        # every returned case must actually involve R1
        for c in r1_only:
            self.assertIn("R1", c["rules"])
        # R1 cases are a subset of all cases
        self.assertLessEqual(len(r1_only), len(all_cases))


class DetectionPipelineTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.login()
        self.seed_settings()

    def _upload_csv(self, rows):
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=[
                "event_id", "timestamp", "account",
                "computer", "event", "department_case"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        data = {"file": (io.BytesIO(buf.getvalue().encode()),
                         "test.csv", "text/csv")}
        return self.client.post(
            "/api/upload", data=data, content_type="multipart/form-data")

    def test_csv_upload_creates_r1_case(self):
        rows = [
            {"event_id": "1", "timestamp": "2025-03-10 09:05:12",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "2", "timestamp": "2025-03-10 09:05:48",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "3", "timestamp": "2025-03-10 09:06:20",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "4", "timestamp": "2025-03-10 09:06:40",
             "account": "a.raj", "computer": "PC-02",
             "event": "Success", "department_case": "CSE"},
        ]
        res = self._upload_csv(rows)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["events"], 4)
        cases = self.client.get("/api/dashboard").get_json()["cases"]
        r1 = [c for c in cases if c["account"] == "a.raj"
              and c["computer"] == "PC-02"]
        self.assertEqual(len(r1), 1)
        self.assertTrue(r1[0]["r1"])
        self.assertIn("R1", r1[0]["rules"])
        self.assertEqual(r1[0]["severity"], "Medium")

    def test_case_detail_returns_evidence(self):
        rows = [
            {"event_id": "1", "timestamp": "2025-03-10 09:05:12",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "2", "timestamp": "2025-03-10 09:05:48",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "3", "timestamp": "2025-03-10 09:06:20",
             "account": "a.raj", "computer": "PC-02",
             "event": "Failure", "department_case": "CSE"},
            {"event_id": "4", "timestamp": "2025-03-10 09:06:40",
             "account": "a.raj", "computer": "PC-02",
             "event": "Success", "department_case": "CSE"},
        ]
        self._upload_csv(rows)
        cases = self.client.get("/api/dashboard").get_json()["cases"]
        case_id = [c for c in cases if c["r1"]][0]["id"]
        res = self.client.get(f"/api/cases/{case_id}")
        self.assertEqual(res.status_code, 200)
        c = res.get_json()
        self.assertTrue(c["r1"])
        self.assertIsInstance(c["events"], list)
        self.assertTrue(len(c["events"]) >= 4)
        self.assertIsInstance(c["rule_details"], list)
        self.assertEqual(c["rule_details"][0]["id"], "R1")
        self.assertIn("explanation", c["rule_details"][0])
        self.assertIn("recommendation", c["rule_details"][0])
        self.assertIn("threshold", c["rule_details"][0])
        self.assertIn("window", c["rule_details"][0])
        self.assertIn("matchedEventIds", c["rule_details"][0])

    def test_confirm_dismiss_workflow(self):
        rows = [
            {"event_id": "1", "timestamp": "2025-03-10 02:15:00",
             "account": "x.user", "computer": "PC-01",
             "event": "Success", "department_case": "CSE"},
        ]
        self._upload_csv(rows)
        cases = self.client.get("/api/dashboard").get_json()["cases"]
        case_id = [c for c in cases if c["r2"]][0]["id"]
        # confirm
        res = self.client.post(
            f"/api/cases/{case_id}/action",
            data=json.dumps({"action": "confirm"}),
            content_type="application/json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "confirmed")
        c = self.client.get(f"/api/cases/{case_id}").get_json()
        self.assertEqual(c["status"], "confirmed")
        # dismiss
        res = self.client.post(
            f"/api/cases/{case_id}/action",
            data=json.dumps({"action": "dismiss"}),
            content_type="application/json")
        self.assertEqual(res.get_json()["status"], "dismissed")
        # escalate reopens as PRIORITY
        res = self.client.post(
            f"/api/cases/{case_id}/action",
            data=json.dumps({"action": "escalate"}),
            content_type="application/json")
        self.assertEqual(res.status_code, 200)
        c = self.client.get(f"/api/cases/{case_id}").get_json()
        self.assertEqual(c["status"], "open")
        self.assertEqual(c["priority"], "PRIORITY")
        # invalid action rejected
        res = self.client.post(
            f"/api/cases/{case_id}/action",
            data=json.dumps({"action": "nope"}),
            content_type="application/json")
        self.assertEqual(res.status_code, 400)

    def test_audit_log_records_actions(self):
        self.client.post(
            "/api/cases/999999/action",
            data=json.dumps({"action": "confirm"}),
            content_type="application/json")  # 404-ish, but audited path
        res = self.client.get("/api/audit")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)


class SchedulerDedupTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.seed_settings()

    def _insert_raw(self, rows):
        conn = sqlite3.connect(self.db_path)
        conn.executemany(
            """INSERT INTO raw_logs
               (timestamp, source, host, account, computer, event,
                message, severity, line_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
        conn.close()

    def test_repeated_runs_do_not_duplicate_cases(self):
        now = "2025-03-10 09:05:12"
        rows = [
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f1", "Informational", "hash-1"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f2", "Informational", "hash-2"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f3", "Informational", "hash-3"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Success",
             "s1", "Informational", "hash-4"),
        ]
        self._insert_raw(rows)
        # first pass
        new_rows, created, updated = app.scheduler.run_detection()
        self.assertEqual(new_rows, 4)
        self.assertGreaterEqual(created, 1)
        cases_after_first = self._case_count()
        # second pass with no new rows → nothing to do
        new_rows, created, updated = app.scheduler.run_detection()
        self.assertEqual(new_rows, 0)
        self.assertEqual(created, 0)
        self.assertEqual(self._case_count(), cases_after_first)
        # third pass: reset the detector cursor and reprocess the
        # SAME rows → upsert by case_key, still no duplicates
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE collector_state SET last_position=0 "
            "WHERE source='detector'")
        conn.commit()
        conn.close()
        new_rows, created, updated = app.scheduler.run_detection()
        self.assertEqual(new_rows, 4)
        self.assertEqual(self._case_count(), cases_after_first)

    def _case_count(self):
        conn = sqlite3.connect(self.db_path)
        n = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        conn.close()
        return n

    def test_rule_matches_recorded_and_deduped(self):
        now = "2025-03-10 09:05:12"
        rows = [
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f1", "Informational", "hash-1"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f2", "Informational", "hash-2"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Failure",
             "f3", "Informational", "hash-3"),
            (now, "file", "PC-02", "a.raj", "PC-02", "Success",
             "s1", "Informational", "hash-4"),
        ]
        self._insert_raw(rows)
        app.scheduler.run_detection()
        conn = sqlite3.connect(self.db_path)
        n = conn.execute("SELECT COUNT(*) FROM rule_matches").fetchone()[0]
        fps = conn.execute(
            "SELECT COUNT(DISTINCT fingerprint) FROM rule_matches"
        ).fetchone()[0]
        conn.close()
        self.assertGreaterEqual(n, 1)
        self.assertEqual(n, fps)  # one row per distinct fingerprint

    def test_r6_fires_on_second_distinct_burst(self):
        # first R1 burst
        self._insert_raw([
            ("2025-03-10 09:05:00", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f1", "Informational", "h1"),
            ("2025-03-10 09:05:20", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f2", "Informational", "h2"),
            ("2025-03-10 09:05:40", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f3", "Informational", "h3"),
            ("2025-03-10 09:05:50", "file", "PC-02", "a.raj",
             "PC-02", "Success", "s1", "Informational", "h4"),
        ])
        app.scheduler.run_detection()
        # a second, distinct R1 burst 6 hours later (same account+PC)
        self._insert_raw([
            ("2025-03-10 15:05:00", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f5", "Informational", "h5"),
            ("2025-03-10 15:05:20", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f6", "Informational", "h6"),
            ("2025-03-10 15:05:40", "file", "PC-02", "a.raj",
             "PC-02", "Failure", "f7", "Informational", "h7"),
            ("2025-03-10 15:05:50", "file", "PC-02", "a.raj",
             "PC-02", "Success", "s2", "Informational", "h8"),
        ])
        app.scheduler.run_detection()
        conn = sqlite3.connect(self.db_path)
        r6 = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE r6=1").fetchone()[0]
        conn.close()
        self.assertGreaterEqual(r6, 1)


class MonitorApiTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.login()

    def test_monitor_overview(self):
        res = self.client.get("/api/monitor/overview")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("totalLogs", data)
        self.assertIn("cases", data)

    def test_monitor_collections(self):
        for endpoint in (
                "/api/monitor/events-timeline",
                "/api/monitor/sources-timeline",
                "/api/monitor/total-timeline",
                "/api/monitor/collectors",
                "/api/monitor/server",
                "/api/monitor/syslog-stats",
                "/api/monitor/alerts",
                "/api/monitor/banner"):
            res = self.client.get(endpoint)
            self.assertEqual(res.status_code, 200, endpoint)

    def test_monitor_pages_load(self):
        self.assertEqual(self.client.get("/monitor").status_code, 200)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)


if __name__ == "__main__":
    unittest.main()
