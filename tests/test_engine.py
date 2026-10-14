"""Unit tests for the LogLens detection engine (R1–R6).

Run from the project root:
    python -m unittest discover -s tests -t .
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import (  # noqa: E402
    detect_cases, parse_ts, format_ts, is_outside_hours,
    fingerprint, RULE_NAMES, RULE_WEIGHTS,
)


def ev(eid, ts, account, computer, event, dept="CSE"):
    return {"event_id": eid, "timestamp": ts, "account": account,
            "computer": computer, "event": event,
            "department_case": dept}


def find_case(cases, account, computer):
    for c in cases:
        if c["account"] == account and c["computer"] == computer:
            return c
    return None


# ─── R1 ──────────────────────────────────────────────────────


class R1Tests(unittest.TestCase):
    def test_failure_burst_then_success(self):
        events = [
            ev("1", "2025-03-10 09:05:12", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:48", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:20", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 09:06:40", "a.raj", "PC-02", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r1"])
        self.assertFalse(case["r2"])
        self.assertEqual(case["priority"], "REVIEW")
        self.assertIn("R1", case["rules"])
        self.assertEqual(case["r1_detail"]["failCount"], 3)
        self.assertEqual(case["r1_detail"]["windowMin"], 5)
        self.assertEqual(case["r1_detail"]["from"], "2025-03-10 09:05:12")
        self.assertEqual(case["r1_detail"]["successAt"], "2025-03-10 09:06:40")
        self.assertEqual(case["matched_event_ids"], ["1", "2", "3", "4"])
        # explanation is derived from the matched events
        r1_view = [r for r in case["rule_details"] if r["id"] == "R1"][0]
        self.assertIn("3 failed login attempt(s)", r1_view["explanation"])
        self.assertIn("a.raj", r1_view["explanation"])
        self.assertIn("PC-02", r1_view["explanation"])
        self.assertEqual(r1_view["matchedEventIds"], ["1", "2", "3", "4"])
        self.assertEqual(r1_view["recommendation"],
                         "Verify the account holder and review the session.")

    def test_burst_below_threshold_no_r1(self):
        events = [
            ev("1", "2025-03-10 09:05:12", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:48", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:20", "a.raj", "PC-02", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertFalse(case["r1"])
        self.assertEqual(case["priority"], "ROUTINE")

    def test_burst_spread_outside_window_no_r1(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 10:05:00", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 11:05:00", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 11:06:00", "a.raj", "PC-02", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertFalse(case["r1"])
        self.assertEqual(case["priority"], "ROUTINE")


# ─── R2 ──────────────────────────────────────────────────────


class R2Tests(unittest.TestCase):
    def test_after_hours_success(self):
        events = [
            ev("1", "2025-03-10 02:15:00", "x.user", "PC-01", "Success"),
        ]
        cases = detect_cases(events, open_time="08:30", close_time="17:30")
        case = find_case(cases, "x.user", "PC-01")
        self.assertTrue(case["r2"])
        self.assertFalse(case["r1"])
        self.assertEqual(case["priority"], "REVIEW")
        self.assertIn("R2", case["rules"])
        self.assertEqual(case["r2_detail"]["at"], "2025-03-10 02:15:00")
        self.assertEqual(case["r2_detail"]["openTime"], "08:30")
        self.assertEqual(case["r2_detail"]["closeTime"], "17:30")
        r2_view = [r for r in case["rule_details"] if r["id"] == "R2"][0]
        self.assertIn("outside the configured lab hours", r2_view["explanation"])
        self.assertEqual(r2_view["matchedEventIds"], ["1"])
        self.assertEqual(r2_view["recommendation"],
                         "Verify whether the access was authorized.")

    def test_within_hours_no_r2(self):
        events = [
            ev("1", "2025-03-10 12:00:00", "x.user", "PC-01", "Success"),
        ]
        cases = detect_cases(events, open_time="08:30", close_time="17:30")
        case = find_case(cases, "x.user", "PC-01")
        self.assertFalse(case["r2"])
        self.assertEqual(case["priority"], "ROUTINE")

    def test_boundary_close_time_is_after_hours(self):
        # 17:30 exactly is outside (>= close)
        self.assertTrue(is_outside_hours(parse_ts("2025-03-10 17:30:00"),
                                         "08:30", "17:30"))
        self.assertFalse(is_outside_hours(parse_ts("2025-03-10 17:29:00"),
                                          "08:30", "17:30"))
        self.assertTrue(is_outside_hours(parse_ts("2025-03-10 08:29:00"),
                                         "08:30", "17:30"))


# ─── R3 ──────────────────────────────────────────────────────


class R3Tests(unittest.TestCase):
    def test_failure_burst_without_success(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r3"])
        self.assertFalse(case["r1"])
        self.assertEqual(case["priority"], "REVIEW")
        self.assertIn("R3", case["rules"])
        self.assertEqual(case["r3_detail"]["failCount"], 3)
        self.assertEqual(case["r3_detail"]["eventIds"], ["1", "2", "3"])
        r3_view = [r for r in case["rule_details"] if r["id"] == "R3"][0]
        self.assertIn("no successful login", r3_view["explanation"])
        self.assertEqual(r3_view["recommendation"],
                         "Inspect the source events and check for a "
                         "legitimate explanation.")

    def test_burst_with_success_is_r1_not_r3(self):
        # a success inside the window resolves the burst → R1, not R3
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 09:06:30", "a.raj", "PC-02", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r1"])
        self.assertFalse(case["r3"])

    def test_no_duplicate_alerts_for_overlapping_windows(self):
        # 5 failures inside one 5-minute window, no success.
        # Deterministic clustering must yield exactly ONE R3 detail.
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:20", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:05:40", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
            ev("5", "2025-03-10 09:06:20", "a.raj", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r3"])
        # a single R3 rule view, single detail, all 5 events preserved
        self.assertEqual(len([r for r in case["rule_details"]
                               if r["id"] == "R3"]), 1)
        self.assertEqual(case["r3_detail"]["failCount"], 5)
        self.assertEqual(case["matched_event_ids"],
                         ["1", "2", "3", "4", "5"])

    def test_two_distinct_bursts_still_one_case(self):
        # two non-overlapping bursts → still one account@computer case
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 12:00:00", "a.raj", "PC-02", "Failure"),
            ev("5", "2025-03-10 12:00:30", "a.raj", "PC-02", "Failure"),
            ev("6", "2025-03-10 12:01:00", "a.raj", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r3"])
        # the larger cluster (3 failures) is reported
        self.assertEqual(case["r3_detail"]["failCount"], 3)


# ─── R4 ──────────────────────────────────────────────────────


class R4Tests(unittest.TestCase):
    def test_cross_pc_failure_pattern(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-01", "Failure"),
            ev("2", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:07:00", "a.raj", "PC-03", "Failure"),
        ]
        cases = detect_cases(events, r4_window=10)
        r4_cases = [c for c in cases if c["r4"]]
        self.assertEqual(len(r4_cases), 1)
        case = r4_cases[0]
        self.assertEqual(case["account"], "a.raj")
        self.assertEqual(case["r4_detail"]["distinctComputers"], 3)
        self.assertEqual(case["r4_detail"]["computers"],
                         ["PC-01", "PC-02", "PC-03"])
        self.assertEqual(case["matched_event_ids"], ["1", "2", "3"])
        self.assertEqual(case["priority"], "REVIEW")
        view = [r for r in case["rule_details"] if r["id"] == "R4"][0]
        self.assertIn("across 3 lab computers", view["explanation"])
        self.assertEqual(view["recommendation"],
                         "Investigate the related events and verify "
                         "whether the activity is expected.")

    def test_single_pc_no_r4(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-01", "Failure"),
            ev("2", "2025-03-10 09:06:00", "a.raj", "PC-01", "Failure"),
        ]
        cases = detect_cases(events, r4_window=10)
        self.assertEqual([c for c in cases if c["r4"]], [])

    def test_two_pcs_is_enough(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-01", "Failure"),
            ev("2", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, r4_window=10)
        self.assertEqual(len([c for c in cases if c["r4"]]), 1)

    def test_pcs_outside_window_no_r4(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-01", "Failure"),
            ev("2", "2025-03-10 09:30:00", "a.raj", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, r4_window=10)
        self.assertEqual([c for c in cases if c["r4"]], [])

    def test_different_accounts_not_grouped(self):
        # same computer, different accounts → not an R4 pattern
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-01", "Failure"),
            ev("2", "2025-03-10 09:06:00", "v.hari", "PC-02", "Failure"),
        ]
        cases = detect_cases(events, r4_window=10)
        self.assertEqual([c for c in cases if c["r4"]], [])


# ─── R5 ──────────────────────────────────────────────────────


class R5Tests(unittest.TestCase):
    def test_rapid_account_switching(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "u1", "PC-01", "Success"),
            ev("2", "2025-03-10 09:06:00", "u2", "PC-01", "Success"),
            ev("3", "2025-03-10 09:07:00", "u3", "PC-01", "Success"),
            ev("4", "2025-03-10 09:08:00", "u4", "PC-01", "Success"),
        ]
        cases = detect_cases(events, r5_threshold=4, r5_window=10)
        r5_cases = [c for c in cases if c["r5"]]
        self.assertEqual(len(r5_cases), 1)
        case = r5_cases[0]
        self.assertEqual(case["computer"], "PC-01")
        self.assertEqual(case["r5_detail"]["distinctAccounts"], 4)
        self.assertEqual(case["r5_detail"]["accounts"],
                         ["u1", "u2", "u3", "u4"])
        view = [r for r in case["rule_details"] if r["id"] == "R5"][0]
        self.assertIn("distinct accounts", view["explanation"])
        self.assertIn("review signal", view["recommendation"].lower())

    def test_below_threshold_no_r5(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "u1", "PC-01", "Success"),
            ev("2", "2025-03-10 09:06:00", "u2", "PC-01", "Success"),
            ev("3", "2025-03-10 09:07:00", "u3", "PC-01", "Success"),
        ]
        cases = detect_cases(events, r5_threshold=4, r5_window=10)
        self.assertEqual([c for c in cases if c["r5"]], [])

    def test_threshold_is_configurable(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "u1", "PC-01", "Success"),
            ev("2", "2025-03-10 09:06:00", "u2", "PC-01", "Success"),
            ev("3", "2025-03-10 09:07:00", "u3", "PC-01", "Success"),
        ]
        # with threshold=3 the same data qualifies
        cases = detect_cases(events, r5_threshold=3, r5_window=10)
        self.assertEqual(len([c for c in cases if c["r5"]]), 1)

    def test_accounts_outside_window_no_r5(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "u1", "PC-01", "Success"),
            ev("2", "2025-03-10 09:20:00", "u2", "PC-01", "Success"),
            ev("3", "2025-03-10 09:35:00", "u3", "PC-01", "Success"),
            ev("4", "2025-03-10 09:50:00", "u4", "PC-01", "Success"),
        ]
        cases = detect_cases(events, r5_threshold=4, r5_window=10)
        self.assertEqual([c for c in cases if c["r5"]], [])


# ─── R6 ──────────────────────────────────────────────────────


class R6Tests(unittest.TestCase):
    def _burst(self, prefix, start_h, start_m):
        """One R1-qualifying burst: 3 failures (20 s apart) then a
        success, all within a 5-minute window."""
        def ts(sec):
            return "2025-03-10 %02d:%02d:%02d" % (
                start_h, start_m, sec)
        return [
            ev(prefix + "1", ts(0), "a.raj", "PC-02", "Failure"),
            ev(prefix + "2", ts(20), "a.raj", "PC-02", "Failure"),
            ev(prefix + "3", ts(40), "a.raj", "PC-02", "Failure"),
            ev(prefix + "4", ts(50), "a.raj", "PC-02", "Success"),
        ]

    def test_repeated_r1_within_24h(self):
        burst_a = self._burst("a", 9, 5)
        burst_b = self._burst("b", 15, 5)
        prior = [{
            "rule_set": "R1",
            "account": "a.raj",
            "computer": "PC-02",
            "first_ts": "2025-03-10 09:05:00",
            "last_ts": "2025-03-10 09:05:00",
            "fingerprint": fingerprint("a.raj", "PC-02",
                                        ["a1", "a2", "a3", "a4"]),
            "case_key": "a.raj @ PC-02",
            "matched_event_ids": ["a1", "a2", "a3", "a4"],
        }]
        cases = detect_cases(burst_a + burst_b, N=3, W=5,
                               prior_matches=prior)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r1"])
        self.assertTrue(case["r6"])
        self.assertEqual(case["priority"], "PRIORITY")  # escalated
        self.assertEqual(case["r6_detail"]["count"], 2)
        self.assertIn("R1", case["r6_detail"]["rules"])
        view = [r for r in case["rule_details"] if r["id"] == "R6"][0]
        self.assertIn("recurred", view["explanation"])
        self.assertEqual(view["recommendation"],
                         "Review the correlated incidents together.")

    def test_single_occurrence_no_r6(self):
        burst_a = self._burst("a", 9, 5)
        cases = detect_cases(burst_a, N=3, W=5, prior_matches=[])
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r1"])
        self.assertFalse(case["r6"])

    def test_duplicate_scheduler_run_not_a_new_incident(self):
        # prior match has the SAME fingerprint as the current events
        burst_a = self._burst("a", 9, 5)
        prior = [{
            "rule_set": "R1",
            "account": "a.raj",
            "computer": "PC-02",
            "first_ts": "2025-03-10 09:05:00",
            "last_ts": "2025-03-10 09:05:00",
            "fingerprint": fingerprint("a.raj", "PC-02",
                                        ["a1", "a2", "a3", "a4"]),
            "case_key": "a.raj @ PC-02",
            "matched_event_ids": ["a1", "a2", "a3", "a4"],
        }]
        cases = detect_cases(burst_a, N=3, W=5, prior_matches=prior)
        case = find_case(cases, "a.raj", "PC-02")
        # same occurrence counted once → below threshold → no R6
        self.assertFalse(case["r6"])

    def test_r6_only_counts_r1_r2_not_r3(self):
        # an R3 occurrence should not feed the R6 recurrence count
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
        ]
        prior = [{
            "rule_set": "R3",
            "account": "a.raj",
            "computer": "PC-02",
            "first_ts": "2025-03-10 08:00:00",
            "last_ts": "2025-03-10 08:00:00",
            "fingerprint": "old-r3-fingerprint",
            "case_key": "a.raj @ PC-02",
            "matched_event_ids": ["x"],
        }]
        cases = detect_cases(events, N=3, W=5, prior_matches=prior)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r3"])
        self.assertFalse(case["r6"])

    def test_r6_outside_24h_window_no_r6(self):
        burst_a = self._burst("a", 9, 5)
        prior = [{
            "rule_set": "R1",
            "account": "a.raj",
            "computer": "PC-02",
            "first_ts": "2025-03-08 09:05:00",  # > 24 h ago
            "last_ts": "2025-03-08 09:05:00",
            "fingerprint": fingerprint("a.raj", "PC-02",
                                        ["a1", "a2", "a3", "a4"]),
            "case_key": "a.raj @ PC-02",
            "matched_event_ids": ["a1", "a2", "a3", "a4"],
        }]
        cases = detect_cases(burst_a, N=3, W=5, prior_matches=prior)
        case = find_case(cases, "a.raj", "PC-02")
        self.assertTrue(case["r1"])
        self.assertFalse(case["r6"])


# ─── General / safety ────────────────────────────────────────


class GeneralTests(unittest.TestCase):
    def test_normal_logins_no_alerts(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Success"),
            ev("2", "2025-03-10 09:10:00", "v.hari", "PC-03", "Success"),
            ev("3", "2025-03-10 09:15:00", "r.devi", "PC-04", "Success"),
        ]
        cases = detect_cases(events)
        self.assertTrue(cases)
        for c in cases:
            self.assertEqual(c["priority"], "ROUTINE")
            self.assertEqual(c["rules"], [])
            self.assertEqual(c["rule_details"], [])
            self.assertEqual(c["score"], 0)
            for flag in ("r1", "r2", "r3", "r4", "r5", "r6"):
                self.assertFalse(c[flag])

    def test_malformed_and_missing_fields_no_crash(self):
        events = [
            ev("1", "not-a-timestamp", "a.raj", "PC-02", "Failure"),
            ev("2", None, "a.raj", "PC-02", "Success"),
            ev("3", "2025-13-40 99:99:99", "x", "y", "Failure"),
            ev("4", "2025-03-10 09:05:00", "", "", "Failure"),
            {"event_id": "5"},
            "not a dict",
            None,
            ev("6", "2025-03-10 09:05:00", "a.raj", "PC-02", "Info"),
        ]
        cases = detect_cases(events)  # must not raise
        self.assertIsInstance(cases, list)

    def test_duplicate_event_ids_handled(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("1", "2025-03-10 09:05:10", "a.raj", "PC-02", "Failure"),
            ev("1", "2025-03-10 09:05:20", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "a.raj", "PC-02")
        # duplicate ids collapse in the matched set but the burst
        # still qualifies (3 failures then a success)
        self.assertTrue(case["r1"])

    def test_empty_events(self):
        self.assertEqual(detect_cases([]), [])

    def test_r1_r2_combined_is_priority(self):
        events = [
            ev("1", "2025-03-10 02:15:10", "x.user", "PC-01", "Failure"),
            ev("2", "2025-03-10 02:15:45", "x.user", "PC-01", "Failure"),
            ev("3", "2025-03-10 02:16:20", "x.user", "PC-01", "Failure"),
            ev("4", "2025-03-10 02:17:05", "x.user", "PC-01", "Failure"),
            ev("5", "2025-03-10 02:18:00", "x.user", "PC-01", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "x.user", "PC-01")
        self.assertTrue(case["r1"])
        self.assertTrue(case["r2"])
        self.assertEqual(case["priority"], "PRIORITY")
        self.assertEqual(case["severity"], "High")
        self.assertEqual(case["score"], RULE_WEIGHTS["R1"] + RULE_WEIGHTS["R2"])

    def test_score_is_capped_and_documented(self):
        events = [
            ev("1", "2025-03-10 02:15:10", "x.user", "PC-01", "Failure"),
            ev("2", "2025-03-10 02:15:45", "x.user", "PC-01", "Failure"),
            ev("3", "2025-03-10 02:16:20", "x.user", "PC-01", "Failure"),
            ev("4", "2025-03-10 02:17:05", "x.user", "PC-01", "Failure"),
            ev("5", "2025-03-10 02:18:00", "x.user", "PC-01", "Success"),
        ]
        cases = detect_cases(events, N=3, W=5)
        case = find_case(cases, "x.user", "PC-01")
        # R1+R2 = 70, well under the 100 cap
        self.assertLessEqual(case["score"], 100)

    def test_rule_names_complete(self):
        for r in ("R1", "R2", "R3", "R4", "R5", "R6"):
            self.assertIn(r, RULE_NAMES)

    def test_deterministic(self):
        events = [
            ev("1", "2025-03-10 09:05:00", "a.raj", "PC-02", "Failure"),
            ev("2", "2025-03-10 09:05:30", "a.raj", "PC-02", "Failure"),
            ev("3", "2025-03-10 09:06:00", "a.raj", "PC-02", "Failure"),
            ev("4", "2025-03-10 09:06:30", "a.raj", "PC-02", "Success"),
        ]
        first = detect_cases(events, N=3, W=5)
        second = detect_cases(events, N=3, W=5)
        self.assertEqual(
            [(c["case_key"], c["rules"]) for c in first],
            [(c["case_key"], c["rules"]) for c in second],
        )


if __name__ == "__main__":
    unittest.main()
