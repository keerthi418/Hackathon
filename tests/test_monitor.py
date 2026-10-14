"""Tests for the Live Monitor charts, time aggregation and live metrics.

Covers the accuracy fixes for the dashboard:

  * time-bucket aggregation (wall-clock aligned, zero-filled)
  * empty datasets
  * timestamp handling / local-time conversion
  * event-rate (Events/sec) calculation, including deduplicated ingestion
  * per-source counts
  * collector status diagnostics (Windows Security log)

Runs against a temporary SQLite database — the real data/labtrace.db is
never touched.

Run from the project root:
    python -m unittest tests.test_monitor -v
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.config  # noqa: E402
import app.collector  # noqa: E402
import app.main  # noqa: E402
import app.scheduler  # noqa: E402


class MonitorTestCase(unittest.TestCase):
    """Base class that swaps in a temporary database."""

    def setUp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self.db_path = tmp.name
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

    # ── helpers ─────────────────────────────────────────────────
    def login(self):
        res = self.client.post(
            "/login",
            data=json.dumps({"username": "admin", "password": "LabTrace@2025"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)

    def _insert_raw(self, rows):
        """rows: (timestamp, source, account, computer, event, message)."""
        conn = sqlite3.connect(self.db_path)
        conn.executemany(
            """INSERT INTO raw_logs
               (timestamp, source, host, account, computer, event, message,
                severity, line_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            [(ts, src, host, acct, comp, evt, msg, "Informational",
              f"hash-{i}")
             for i, (ts, src, host, acct, comp, evt, msg) in enumerate(rows)],
        )
        conn.commit()
        conn.close()

    def _clear_arrivals(self):
        app.collector.MANAGER.stats._arrivals.clear()


# ─── Bucket grid / time aggregation ──────────────────────────────

class BucketGridTests(unittest.TestCase):

    def test_grid_is_aligned_and_exact(self):
        now = datetime(2026, 10, 14, 12, 3, 45)
        cases = [
            (300, 2 * 3600, 24, "00", "05"),   # 5-minute buckets, 2 h
            (600, 6 * 3600, 36, "00", "00"),   # 10-minute buckets, 6 h
            (3600, 24 * 3600, 24, "00", "00"),  # hourly buckets, 24 h
        ]
        for bucket, span, n, _min, _m in cases:
            start, labels, got_n = app.main._bucket_grid(bucket, span, now=now)
            self.assertEqual(got_n, n)
            self.assertEqual(len(labels), n)
            # aligned to round wall-clock marks
            self.assertEqual(start.second, 0)
            self.assertEqual(start.microsecond, 0)
            self.assertEqual(start.minute % (bucket // 60), 0)
            # last bucket starts at the current (aligned) minute
            self.assertEqual(labels[-1], "12:00")

    def test_bucket_index_local_time(self):
        now = datetime(2026, 10, 14, 12, 0, 0)
        bucket, span = 300, 2 * 3600
        start, labels, n = app.main._bucket_grid(bucket, span, now=now)
        start_epoch = int(start.timestamp())
        # exactly at a bucket start → that bucket
        self.assertEqual(
            app.main._bucket_index("2026-10-14 11:35:00", start_epoch, bucket, n),
            labels.index("11:35"),
        )
        # a few seconds later, still the same bucket
        self.assertEqual(
            app.main._bucket_index("2026-10-14 11:35:30", start_epoch, bucket, n),
            labels.index("11:35"),
        )
        # unparseable timestamp → ignored (never crashes)
        self.assertIsNone(
            app.main._bucket_index("not-a-time", start_epoch, bucket, n)
        )
        # before the window → ignored
        self.assertIsNone(
            app.main._bucket_index("2026-10-14 10:04:59", start_epoch, bucket, n)
        )
        # in the future → ignored
        self.assertIsNone(
            app.main._bucket_index("2026-10-14 13:00:00", start_epoch, bucket, n)
        )


# ─── Chart endpoints ────────────────────────────────────────────

class MonitorChartTests(MonitorTestCase):

    def setUp(self):
        super().setUp()
        self.login()

    def test_empty_dataset_is_zero_filled(self):
        for ep, key in (("/api/monitor/events-timeline", "counts"),
                        ("/api/monitor/total-timeline", "counts")):
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 200, ep)
            d = res.get_json()
            self.assertEqual(d[key], [0] * len(d[key]))
            self.assertEqual(len(d[key]), len(d["labels"]))
            # documented interval
            self.assertEqual(d["bucketSeconds"] > 0, True)
            self.assertEqual(d["spanSeconds"] > 0, True)

    def test_sources_timeline_empty_has_no_series(self):
        d = self.client.get("/api/monitor/sources-timeline").get_json()
        self.assertEqual(d["series"], {})
        self.assertTrue(len(d["labels"]) > 0)

    def test_events_timeline_counts_recent_events(self):
        now = datetime.now()
        rows = [
            ((now - timedelta(minutes=1)).strftime(app.main.TS_FMT),
             "file", "PC-01", "a.raj", "PC-01", "Failure", "m1"),
            ((now - timedelta(minutes=2)).strftime(app.main.TS_FMT),
             "file", "PC-01", "a.raj", "PC-01", "Failure", "m2"),
            ((now - timedelta(hours=5)).strftime(app.main.TS_FMT),
             "file", "PC-01", "a.raj", "PC-01", "Failure", "old"),
        ]
        self._insert_raw(rows)
        d = self.client.get("/api/monitor/events-timeline").get_json()
        # All 3 events are reflected in the chart (the grid extends to
        # include older data so the chart always shows the real
        # event distribution)
        self.assertEqual(sum(d["counts"]), 3)
        self.assertTrue(all(c in (0, 1, 2, 3) for c in d["counts"]))

    def test_sources_timeline_groups_by_source(self):
        now = datetime.now()
        rows = [
            ((now - timedelta(minutes=1)).strftime(app.main.TS_FMT),
             "file", "PC-01", "a.raj", "PC-01", "Success", "m1"),
            ((now - timedelta(minutes=2)).strftime(app.main.TS_FMT),
             "file", "PC-01", "a.raj", "PC-01", "Success", "m2"),
            ((now - timedelta(minutes=3)).strftime(app.main.TS_FMT),
             "syslog_udp", "PC-02", "b.k", "PC-02", "Failure", "m3"),
        ]
        self._insert_raw(rows)
        d = self.client.get("/api/monitor/sources-timeline").get_json()
        self.assertEqual(sum(d["series"].get("file", [])), 2)
        self.assertEqual(sum(d["series"].get("syslog_udp", [])), 1)
        # missing buckets are zero-filled
        self.assertEqual(len(d["series"]["file"]), len(d["labels"]))

    def test_total_timeline_24h_keeps_history(self):
        now = datetime.now()
        rows = []
        for i in range(5):
            rows.append(((now - timedelta(hours=20)).strftime(app.main.TS_FMT),
                         "file", "PC-01", "a.raj", "PC-01", "Success", f"m{i}"))
        for i in range(3):
            rows.append(((now - timedelta(minutes=5)).strftime(app.main.TS_FMT),
                         "file", "PC-01", "a.raj", "PC-01", "Success", f"n{i}"))
        self._insert_raw(rows)
        d = self.client.get("/api/monitor/total-timeline").get_json()
        self.assertEqual(sum(d["counts"]), 8)

    def test_windows_outside_range_are_ignored(self):
        now = datetime.now()
        # 30 h old → outside the 24 h timeline, must not appear
        rows = [((now - timedelta(hours=30)).strftime(app.main.TS_FMT),
                 "file", "PC-01", "a.raj", "PC-01", "Success", "old")]
        self._insert_raw(rows)
        d = self.client.get("/api/monitor/total-timeline").get_json()
        self.assertEqual(sum(d["counts"]), 0)
        ov = self.client.get("/api/monitor/overview").get_json()
        self.assertEqual(ov["totalLogs"], 1)  # …but still a stored log


# ─── Live metrics ───────────────────────────────────────────────

class MonitorMetricsTests(MonitorTestCase):

    def setUp(self):
        super().setUp()
        self.login()

    def test_overview_counts_sources_and_cases(self):
        now = datetime.now()
        rows = []
        for i in range(3):
            rows.append(((now - timedelta(minutes=10)).strftime(app.main.TS_FMT),
                         "file", "PC-01", "a.raj", "PC-01", "Success", f"m{i}"))
        for i in range(4):
            rows.append(((now - timedelta(minutes=20)).strftime(app.main.TS_FMT),
                         "syslog_udp", "PC-02", "b.k", "PC-02", "Failure", f"u{i}"))
        self._insert_raw(rows)
        ov = self.client.get("/api/monitor/overview").get_json()
        self.assertEqual(ov["totalLogs"], 7)
        by_source = {s["source"]: s["count"] for s in ov["sources"]}
        self.assertEqual(by_source, {"file": 3, "syslog_udp": 4})
        # events in the last minute: 0 (the newest is 10 min old)
        self.assertEqual(ov["eventsLastMinute"], 0)
        # events/sec = arrival rate (nothing ingested here) → 0
        self.assertEqual(ov["eventsPerSecond"], 0.0)

    def test_events_last_minute_uses_event_timestamps(self):
        now = datetime.now()
        rows = [((now - timedelta(seconds=20)).strftime(app.main.TS_FMT),
                 "file", "PC-01", "a.raj", "PC-01", "Success", "m1")]
        self._insert_raw(rows)
        ov = self.client.get("/api/monitor/overview").get_json()
        self.assertEqual(ov["eventsLastMinute"], 1)

    def test_cases_metrics(self):
        conn = sqlite3.connect(self.db_path)
        conn.executemany(
            """INSERT INTO cases
               (case_key, account, computer, department, priority, r1, r2,
                reason, human_check, event_count, matched_event_ids,
                r1_detail, r2_detail, status, origin, is_new)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                ("k1", "a", "PC-01", "CSE", "PRIORITY", 1, 0, "r", "n", 1,
                 "[]", "{}", "{}", "open", "live", 1),
                ("k2", "b", "PC-02", "ECE", "REVIEW", 0, 1, "r", "n", 1,
                 "[]", "{}", "{}", "open", "live", 0),
                ("k3", "c", "PC-03", "CSE", "ROUTINE", 0, 0, "r", "n", 1,
                 "[]", "{}", "{}", "confirmed", "live", 0),
            ],
        )
        conn.commit()
        conn.close()
        ov = self.client.get("/api/monitor/overview").get_json()
        self.assertEqual(ov["cases"]["open"], 2)
        self.assertEqual(ov["cases"]["priority"], 1)
        self.assertEqual(ov["cases"]["review"], 1)

    def test_event_rate_zero_when_idle(self):
        self._clear_arrivals()
        self.assertEqual(app.collector.MANAGER.stats.eps(), 0.0)

    def test_event_rate_measured_over_window(self):
        self._clear_arrivals()
        stats = app.collector.MANAGER.stats
        for _ in range(6):
            stats.record_ingest()
        # 6 arrivals in the documented 10 s window → 0.6 events/sec
        self.assertAlmostEqual(stats.eps(), 0.6, places=2)

    def test_duplicate_ingest_does_not_inflate_rate(self):
        self._clear_arrivals()
        self.assertTrue(app.collector.ingest(
            "file", "2026-10-14 12:00:00", host="PC-01", account="a.raj",
            computer="PC-01", event="Success", message="m"))
        # same record again → deduplicated, must not count as a new arrival
        self.assertFalse(app.collector.ingest(
            "file", "2026-10-14 12:00:00", host="PC-01", account="a.raj",
            computer="PC-01", event="Success", message="m"))
        self.assertEqual(len(app.collector.MANAGER.stats._arrivals), 1)


# ─── Collector status diagnostics ───────────────────────────────

class WindowsCollectorTests(unittest.TestCase):

    def _failing_collector(self, py_err, wevt_err):
        c = app.collector.WindowsEventCollector(app.collector.MANAGER)
        c._pywin_err = py_err
        c._wevt_err = wevt_err
        c._ps_err = "mocked failure"
        c.state = lambda: {}
        c._read_powershell = lambda last_ts: None
        c._read_pywin32 = lambda last_ts: None
        c._read_wevtutil = lambda: None
        return c

    def test_access_denied_reports_true_cause(self):
        c = self._failing_collector(
            "pywin32: (1314, 'OpenEventLogW', 'A required privilege is not "
            "held by the client.')",
            "wevtutil rc=5: Access is denied.",
        )
        c.poll()
        # never reports a broken collector as active
        self.assertEqual(c.status, "degraded")
        self.assertIn("Administrator", c.detail)
        self.assertIn("denied", c.detail.lower())
        self.assertNotIn("unavailable", c.detail.lower())

    def test_missing_dependencies_reported_clearly(self):
        c = self._failing_collector(
            "pywin32 not installed (No module named 'win32evtlog')",
            "wevtutil not found ([Errno 2] No such file)",
        )
        c.poll()
        self.assertEqual(c.status, "degraded")
        self.assertIn("pip install pywin32", c.detail)


if __name__ == "__main__":
    unittest.main()
