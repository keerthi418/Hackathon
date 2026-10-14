"""
LogLens Rule Engine — six explainable detection rules (R1–R6).

Every rule is a small, deterministic, independently testable function.
The engine never blocks users, terminates sessions or isolates hosts —
it only produces *explainable* cases for a human to review.

Rules
-----
R1  Failure Burst Followed by Success      (existing)
R2  After-Hours Successful Login           (existing)
R3  Failure Burst Without Success          (new)
R4  Cross-PC Account Failure Pattern       (new)
R5  Rapid Account Switching on a Lab PC    (new)
R6  Repeated Risk Pattern (R1/R2 in 24 h)  (new)

Detection is fully local. No paid APIs, no internet access.

Scoring (optional, transparent):
    score = min(100, sum of the weights of the triggered rules)
    R1=40 R2=30 R3=25 R4=35 R5=15 R6=50
    This is a *rule-based prioritization score*, NOT a probability of
    compromise. It exists only to help analysts triage the queue.
"""
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

# ─── Rule metadata (single source of truth for the UI) ───────────
RULE_NAMES = {
    "R1": "Failure Burst Followed by Success",
    "R2": "After-Hours Successful Login",
    "R3": "Failure Burst Without Success",
    "R4": "Cross-PC Account Failure Pattern",
    "R5": "Rapid Account Switching on a Lab PC",
    "R6": "Repeated Risk Pattern",
}

# Per-rule severity label (informational; case severity is derived
# from the case priority below).
RULE_SEVERITY = {
    "R1": "High",
    "R2": "Medium",
    "R3": "Medium",
    "R4": "Medium",
    "R5": "Low",      # review signal only — high false-positive risk
    "R6": "High",
}

# Rule-based prioritization score weights (see module docstring).
RULE_WEIGHTS = {
    "R1": 40,
    "R2": 30,
    "R3": 25,
    "R4": 35,
    "R5": 15,
    "R6": 50,
}

# Default explanations / recommendations, shown verbatim in the UI.
RULE_EXPLANATIONS = {
    "R1": "Repeated failed login attempts preceded a successful login.",
    "R2": "Access occurred outside the configured lab hours.",
    "R3": "Repeated failed attempts occurred without a successful login "
          "in the observed window.",
    "R4": "Failed access attempts for one account were observed across "
          "multiple lab computers.",
    "R5": "Multiple account sessions appeared on one lab computer within "
          "a short period.",
    "R6": "A risk pattern has recurred for the same account and computer.",
}

RULE_RECOMMENDATIONS = {
    "R1": "Verify the account holder and review the session.",
    "R2": "Verify whether the access was authorized.",
    "R3": "Inspect the source events and check for a legitimate explanation.",
    "R4": "Investigate the related events and verify whether the activity "
          "is expected.",
    "R5": "Review session history and confirm whether the pattern is normal "
          "for that lab.",
    "R6": "Review the correlated incidents together.",
}

# R5 is a weak signal shared labs produce by design.
R5_FALSE_POSITIVE_NOTE = (
    "Note: shared labs naturally have many users. Treat this as a review "
    "signal, not proof of malicious activity."
)

PRIORITY_ORDER = {"PRIORITY": 0, "REVIEW": 1, "ROUTINE": 2}
SEVERITY_BY_PRIORITY = {"PRIORITY": "High", "REVIEW": "Medium",
                        "ROUTINE": "Low"}


# ─── Timestamp helpers ─────────────────────────────────────────────


def parse_ts(s):
    """Parse flexible timestamp formats → datetime or None (never raises)."""
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    s_str = str(s).strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S"
    ):
        try:
            return datetime.strptime(s_str.rstrip("Z"), fmt)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(s_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def format_ts(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else None


def is_outside_hours(dt, open_str="08:30", close_str="17:30"):
    """True when a datetime is outside the configured lab open/close."""
    try:
        oh, om = map(int, str(open_str).split(":"))
        ch, cm = map(int, str(close_str).split(":"))
    except Exception:
        return False
    mins = dt.hour * 60 + dt.minute
    return mins < (oh * 60 + om) or mins >= (ch * 60 + cm)


# ─── Fingerprinting (deterministic dedup key for an occurrence) ────


def fingerprint(account, computer, event_ids):
    """Stable SHA-256 over account, computer and the matched event IDs.

    The same set of events always yields the same fingerprint, so a
    repeated scheduler run over unchanged data never counts as a new
    incident (this is what makes R6 de-duplicate scheduler runs).
    """
    ids = sorted(set(str(i) for i in (event_ids or []) if str(i).strip()))
    payload = "{}|{}|{}".format(
        str(account).strip(), str(computer).strip(), ",".join(ids)
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


# ─── Normalization ─────────────────────────────────────────────────


def _normalize(events):
    """Filter + normalize raw event dicts. Malformed rows are skipped.

    Windows-specific fields (logon_type, source_ip, source_workstation,
    auth_package, domain) are preserved for explainable detection.
    """
    normalized = []
    for e in events:
        if not isinstance(e, dict):
            continue
        raw_ts = e.get("timestamp")
        ts = raw_ts if isinstance(raw_ts, datetime) else parse_ts(raw_ts)
        if not ts:
            continue
        evt = str(e.get("event", "")).strip().capitalize()
        if evt not in ("Failure", "Success"):
            continue
        normalized.append({
            "event_id": str(e.get("event_id", "")),
            "timestamp": ts,
            "account": str(e.get("account", "")).strip(),
            "computer": str(e.get("computer", "")).strip(),
            "event": evt,
            "department_case": str(
                e.get("department_case", e.get("department", ""))
            ),
            # Windows-specific fields (empty for non-Windows events)
            "logon_type": str(e.get("logon_type", "")).strip(),
            "source_ip": str(e.get("source_ip", "")).strip(),
            "source_workstation": str(e.get("source_workstation", "")).strip(),
            "auth_package": str(e.get("auth_package", "")).strip(),
            "domain": str(e.get("domain", "")).strip(),
        })
    return normalized


# ─── Clustering (deterministic, non-overlapping windows) ───────────


def _cluster_events(evts, window_minutes):
    """Greedy non-overlapping clusters.

    Each cluster starts at the first not-yet-consumed event and spans
    `window_minutes`. Advancing past the whole cluster guarantees a
    single event belongs to exactly one cluster, so overlapping windows
    never produce duplicate alerts.
    """
    clusters = []
    i = 0
    n = len(evts)
    while i < n:
        start = evts[i]["timestamp"]
        end = start + timedelta(minutes=window_minutes)
        cluster = []
        j = i
        while j < n and evts[j]["timestamp"] <= end:
            cluster.append(evts[j])
            j += 1
        clusters.append(cluster)
        i = j
    return clusters


# ─── R3 — Failure Burst Without Success ────────────────────────────


def _detect_r3(failures, successes, n, w):
    """A cluster of >= n failures within w minutes with NO success in
    [cluster_start, cluster_start + w]. Returns the most severe
    (largest) qualifying cluster, or None."""
    success_ts = [s["timestamp"] for s in successes]
    best = None
    for cluster in _cluster_events(failures, w):
        if len(cluster) < n:
            continue
        start = cluster[0]["timestamp"]
        end = start + timedelta(minutes=w)
        # a success inside the window "resolves" the burst → R1 territory
        if any(start <= t <= end for t in success_ts):
            continue
        if best is None or len(cluster) > len(best):
            best = cluster
    if best is None:
        return None
    return {
        "failCount": len(best),
        "windowMin": w,
        "threshold": n,
        "from": format_ts(best[0]["timestamp"]),
        "to": format_ts(best[-1]["timestamp"]),
        "eventIds": [e["event_id"] for e in best],
    }


# ─── R6 — Repeated Risk Pattern ────────────────────────────────────


def _detect_r6(account, computer, matched_ids, current_first_ts,
               current_last_ts, current_rules, r6_threshold, r6_hours,
               prior_matches):
    """Count distinct R1/R2 occurrences for this account+computer within
    a rolling r6_hours window. Duplicate scheduler runs share a
    fingerprint and are therefore counted once."""
    if not prior_matches:
        return None
    cutoff = current_last_ts - timedelta(hours=r6_hours)
    fps = {fingerprint(account, computer, matched_ids)}
    rules_involved = set(current_rules)
    related_event_ids = set(matched_ids)
    related_case_keys = set()
    first_ts = current_first_ts
    last_ts = current_last_ts
    for m in prior_matches:
        m_rules = [r.strip() for r in
                   str(m.get("rule_set", "")).split(",") if r.strip()]
        if not any(r in ("R1", "R2") for r in m_rules):
            continue
        if str(m.get("account", "")).strip() != account:
            continue
        if str(m.get("computer", "")).strip() != computer:
            continue
        m_last = parse_ts(m.get("last_ts"))
        if not m_last or not (cutoff < m_last <= current_last_ts):
            continue
        fps.add(m.get("fingerprint"))
        related_case_keys.add(m.get("case_key"))
        for eid in (m.get("matched_event_ids") or []):
            related_event_ids.add(str(eid))
        for r in m_rules:
            if r in ("R1", "R2"):
                rules_involved.add(r)
        m_first = parse_ts(m.get("first_ts"))
        if m_first and (first_ts is None or m_first < first_ts):
            first_ts = m_first
        if m_last and (last_ts is None or m_last > last_ts):
            last_ts = m_last
    if len(fps) < r6_threshold:
        return None
    return {
        "count": len(fps),
        "threshold": r6_threshold,
        "hours": r6_hours,
        "firstTs": format_ts(first_ts),
        "lastTs": format_ts(last_ts),
        "rules": sorted(rules_involved),
        "relatedCaseKeys": sorted(c for c in related_case_keys if c),
        "relatedEventIds": sorted(related_event_ids),
        "fingerprints": sorted(f for f in fps if f),
    }


# ─── Per account+computer rules (R1, R2, R3, R6) ───────────────────


def _detect_account_computer(evts, account, computer, n, w,
                             open_time, close_time,
                             r6_threshold, r6_hours, prior_matches):
    """Return one case dict for a single account@computer group."""
    failures = [e for e in evts if e["event"] == "Failure"]
    successes = [e for e in evts if e["event"] == "Success"]
    r1 = r2 = r3 = r6 = False
    r1_detail = r2_detail = r3_detail = r6_detail = None
    matched_ids = set()

    # ── R1 + R2 (existing logic, preserved) ────────────────────────
    for e in evts:
        if e["event"] == "Failure":
            continue
        # R1: look back w minutes for >= n failures
        window_start = e["timestamp"] - timedelta(minutes=w)
        recent = [f for f in failures
                  if window_start <= f["timestamp"] < e["timestamp"]]
        if len(recent) >= n:
            r1 = True
            # Collect Windows-specific context for the explanation
            src_ips = sorted({f.get("source_ip", "") for f in recent
                             if f.get("source_ip", "")})
            logon_types = sorted({f.get("logon_type", "") for f in recent
                                  if f.get("logon_type", "")})
            r1_detail = {
                "failCount": len(recent),
                "windowMin": w,
                "threshold": n,
                "from": format_ts(recent[0]["timestamp"]),
                "to": format_ts(e["timestamp"]),
                "successAt": format_ts(e["timestamp"]),
                "eventIds": [f["event_id"] for f in recent] + [e["event_id"]],
                "sourceIps": src_ips,
                "logonTypes": logon_types,
                "successLogonType": e.get("logon_type", ""),
                "successSourceIp": e.get("source_ip", ""),
            }
            for f in recent:
                matched_ids.add(f["event_id"])
            matched_ids.add(e["event_id"])
        # R2: after-hours success
        if is_outside_hours(e["timestamp"], open_time, close_time):
            r2 = True
            r2_detail = {
                "at": format_ts(e["timestamp"]),
                "eventId": e["event_id"],
                "eventIds": [e["event_id"]],
                "openTime": open_time,
                "closeTime": close_time,
                "logonType": e.get("logon_type", ""),
                "sourceIp": e.get("source_ip", ""),
            }
            matched_ids.add(e["event_id"])

    # ── R3 ─────────────────────────────────────────────────────────
    r3_detail = _detect_r3(failures, successes, n, w)
    if r3_detail:
        r3 = True
        matched_ids.update(r3_detail["eventIds"])

    # ── R6 (only when R1 or R2 fired) ──────────────────────────────
    current_rules = [r for r, flag in (("R1", r1), ("R2", r2)) if flag]
    if current_rules:
        matched_ts = [e["timestamp"] for e in evts
                      if e["event_id"] in matched_ids] or \
                     [e["timestamp"] for e in evts]
        r6_detail = _detect_r6(
            account, computer, matched_ids,
            min(matched_ts), max(matched_ts),
            current_rules, r6_threshold, r6_hours, prior_matches,
        )
        if r6_detail:
            r6 = True

    # ── priority + reason + human_check (existing strings preserved) ─
    if r1 and r2:
        priority = "PRIORITY"
        reason = (f"{r1_detail['failCount']} failures → success within "
                  f"{w} min AND after-hours login")
        human_check = ("Was this after-hours login allowed? Verify whether "
                       "the account holder or an authorized person was "
                       "expected.")
    elif r1:
        priority = "REVIEW"
        reason = f"{r1_detail['failCount']} failures → success within {w} min window"
        human_check = ("Was this a scheduled guest / shared session or "
                       "legitimate password retry?")
    elif r2:
        priority = "REVIEW"
        reason = f"Successful login outside lab hours ({open_time}–{close_time})"
        human_check = ("Was after-hours access pre-approved for this "
                       "account / machine?")
    elif r3:
        priority = "REVIEW"
        reason = (f"{r3_detail['failCount']} failures without success "
                  f"within {w} min")
        human_check = ("Inspect the source events and check for a "
                       "legitimate explanation.")
    else:
        priority = "ROUTINE"
        total_fails = len(failures)
        if total_fails == 0:
            reason = "No failures observed"
        elif total_fails < n:
            reason = f"{total_fails} failure(s) — below threshold N={n}"
        else:
            reason = (f"{total_fails} failure(s) spread outside window "
                      f"W={w} min (no burst before success)")
        human_check = None

    # R6 escalates an existing R1/R2 case to PRIORITY.
    if r6:
        priority = "PRIORITY"
        reason = (f"{r6_detail['count']} R1/R2 detections in "
                  f"{r6_hours}h — " + reason)
        human_check = ("A risk pattern recurred for this account and "
                       "computer. Review the correlated incidents together.")

    triggered = [r for r, flag in (
        ("R1", r1), ("R2", r2), ("R3", r3), ("R6", r6)) if flag]

    return {
        "case_key": f"{account} @ {computer}",
        "account": account,
        "computer": computer,
        "department": evts[0]["department_case"] if evts else "",
        "priority": priority,
        "severity": SEVERITY_BY_PRIORITY[priority],
        "r1": r1, "r2": r2, "r3": r3, "r4": False, "r5": False, "r6": r6,
        "reason": reason,
        "human_check": human_check,
        "event_count": len(evts),
        "matched_event_ids": sorted(matched_ids),
        "r1_detail": r1_detail,
        "r2_detail": r2_detail,
        "r3_detail": r3_detail,
        "r4_detail": None,
        "r5_detail": None,
        "r6_detail": r6_detail,
        "rules": triggered,
        "rule_details": _build_rule_details(
            triggered, account, computer,
            {"R1": r1_detail, "R2": r2_detail, "R3": r3_detail,
             "R6": r6_detail},
            n, w, open_time, close_time,
        ),
        "score": _compute_score(triggered),
        "events": [
            {"event_id": e["event_id"],
             "timestamp": format_ts(e["timestamp"]),
             "event": e["event"]}
            for e in evts
        ],
        "status": "open",
    }


# ─── R4 — Cross-PC Account Failure Pattern ─────────────────────────


def _detect_r4(normalized, r4_window):
    """Failed logins for one account across >= 2 distinct computers
    within a rolling r4_window. Returns one case per qualifying cluster.

    A shared public IP is NOT treated as evidence of a shared attacker —
    grouping is strictly by (account, computer, timestamp)."""
    by_account = defaultdict(list)
    for e in normalized:
        if e["event"] == "Failure" and e["account"]:
            by_account[e["account"]].append(e)

    cases = []
    for account, fails in by_account.items():
        fails.sort(key=lambda x: x["timestamp"])
        for cluster in _cluster_events(fails, r4_window):
            pcs = sorted({f["computer"] for f in cluster if f["computer"]})
            if len(pcs) < 2:
                continue
            ids = [f["event_id"] for f in cluster]
            first = cluster[0]["timestamp"]
            last = cluster[-1]["timestamp"]
            cases.append({
                "case_key": f"{account} @ {', '.join(pcs)} · {format_ts(first)}",
                "account": account,
                "computer": ", ".join(pcs),
                "department": cluster[0]["department_case"],
                "priority": "REVIEW",
                "severity": "Medium",
                "r1": False, "r2": False, "r3": False,
                "r4": True, "r5": False, "r6": False,
                "reason": (f"{len(cluster)} failed logins for {account} "
                           f"across {len(pcs)} lab PCs within "
                           f"{r4_window} min"),
                "human_check": ("Investigate the related events and verify "
                                "whether the activity is expected."),
                "event_count": len(cluster),
                "matched_event_ids": sorted(ids),
                "r1_detail": None, "r2_detail": None, "r3_detail": None,
                "r4_detail": {
                    "failCount": len(cluster),
                    "distinctComputers": len(pcs),
                    "computers": pcs,
                    "windowMin": r4_window,
                    "from": format_ts(first),
                    "to": format_ts(last),
                    "eventIds": ids,
                },
                "r5_detail": None, "r6_detail": None,
                "rules": ["R4"],
                "rule_details": _build_rule_details(
                    ["R4"], account, ", ".join(pcs), {"R4": {
                        "failCount": len(cluster),
                        "distinctComputers": len(pcs),
                        "computers": pcs,
                        "windowMin": r4_window,
                        "from": format_ts(first),
                        "to": format_ts(last),
                        "eventIds": ids,
                    }}, 3, 5, "08:30", "17:30"),
                "score": _compute_score(["R4"]),
                "events": [
                    {"event_id": f["event_id"],
                     "timestamp": format_ts(f["timestamp"]),
                     "event": f["event"]}
                    for f in cluster
                ],
                "status": "open",
            })
    return cases


# ─── R5 — Rapid Account Switching on a Lab PC ──────────────────────


def _detect_r5(normalized, r5_threshold, r5_window):
    """>= r5_threshold distinct accounts with successful logins on the
    same computer within a rolling r5_window. Returns one case per
    qualifying cluster. This is a *review signal*, not proof of
    malicious activity."""
    by_computer = defaultdict(list)
    for e in normalized:
        if e["event"] == "Success" and e["computer"]:
            by_computer[e["computer"]].append(e)

    cases = []
    for computer, succs in by_computer.items():
        succs.sort(key=lambda x: x["timestamp"])
        for cluster in _cluster_events(succs, r5_window):
            accounts = sorted({s["account"] for s in cluster if s["account"]})
            if len(accounts) < r5_threshold:
                continue
            ids = [s["event_id"] for s in cluster]
            first = cluster[0]["timestamp"]
            last = cluster[-1]["timestamp"]
            cases.append({
                "case_key": f"{', '.join(accounts)} @ {computer} · {format_ts(first)}",
                "account": ", ".join(accounts),
                "computer": computer,
                "department": cluster[0]["department_case"],
                "priority": "REVIEW",
                "severity": "Low",
                "r1": False, "r2": False, "r3": False,
                "r4": False, "r5": True, "r6": False,
                "reason": (f"{len(accounts)} distinct accounts logged in "
                           f"on {computer} within {r5_window} min"),
                "human_check": ("Review session history and confirm whether "
                                "the pattern is normal for that lab."),
                "event_count": len(cluster),
                "matched_event_ids": sorted(ids),
                "r1_detail": None, "r2_detail": None, "r3_detail": None,
                "r4_detail": None,
                "r5_detail": {
                    "distinctAccounts": len(accounts),
                    "accounts": accounts,
                    "threshold": r5_threshold,
                    "windowMin": r5_window,
                    "from": format_ts(first),
                    "to": format_ts(last),
                    "eventIds": ids,
                },
                "r6_detail": None,
                "rules": ["R5"],
                "rule_details": _build_rule_details(
                    ["R5"], ", ".join(accounts), computer, {"R5": {
                        "distinctAccounts": len(accounts),
                        "accounts": accounts,
                        "threshold": r5_threshold,
                        "windowMin": r5_window,
                        "from": format_ts(first),
                        "to": format_ts(last),
                        "eventIds": ids,
                    }}, 3, 5, "08:30", "17:30"),
                "score": _compute_score(["R5"]),
                "events": [
                    {"event_id": s["event_id"],
                     "timestamp": format_ts(s["timestamp"]),
                     "event": s["event"]}
                    for s in cluster
                ],
                "status": "open",
            })
    return cases


# ─── Explainability helpers ────────────────────────────────────────


def _build_rule_details(triggered, account, computer, details,
                        n, w, open_time, close_time):
    """Build the human-readable per-rule view shown in the Evidence Panel."""
    out = []
    for rule in triggered:
        d = details.get(rule) or {}
        if rule == "R1":
            explanation = (
                f"{d.get('failCount')} failed login attempt(s) for "
                f"{account} on {computer} between {d.get('from')} and "
                f"{d.get('to')} were followed by a successful login at "
                f"{d.get('successAt')}.")
            # Add Windows-specific context when available
            src_ips = d.get("sourceIps") or []
            logon_types = d.get("logonTypes") or []
            if src_ips:
                explanation += f" Source IP(s): {', '.join(src_ips)}."
            if logon_types:
                explanation += f" Logon type(s): {', '.join(logon_types)}."
            if d.get("successLogonType"):
                explanation += (f" Successful logon type: "
                                f"{d['successLogonType']}.")
            recommendation = RULE_RECOMMENDATIONS["R1"]
            threshold = f"N={d.get('threshold', n)} failures"
            window = f"W={d.get('windowMin', w)} min"
        elif rule == "R2":
            explanation = (
                f"A successful login for {account} on {computer} occurred "
                f"at {d.get('at')}, outside the configured lab hours "
                f"({d.get('openTime', open_time)}–{d.get('closeTime', close_time)}).")
            if d.get("logonType"):
                explanation += f" Logon type: {d['logonType']}."
            if d.get("sourceIp"):
                explanation += f" Source IP: {d['sourceIp']}."
            recommendation = RULE_RECOMMENDATIONS["R2"]
            threshold = "outside lab hours"
            window = (f"{d.get('openTime', open_time)}–"
                      f"{d.get('closeTime', close_time)}")
        elif rule == "R3":
            explanation = (
                f"{d.get('failCount')} failed login attempt(s) for "
                f"{account} on {computer} between {d.get('from')} and "
                f"{d.get('to')} with no successful login in the "
                f"{d.get('windowMin', w)}-minute window.")
            recommendation = RULE_RECOMMENDATIONS["R3"]
            threshold = f"N={d.get('threshold', n)} failures"
            window = f"W={d.get('windowMin', w)} min"
        elif rule == "R4":
            explanation = (
                f"{d.get('failCount')} failed login attempt(s) for account "
                f"{account} were observed across "
                f"{d.get('distinctComputers')} lab computers "
                f"({', '.join(d.get('computers', []))}) within a "
                f"{d.get('windowMin')}-minute window.")
            recommendation = RULE_RECOMMENDATIONS["R4"]
            threshold = "≥ 2 distinct computers"
            window = f"W={d.get('windowMin')} min"
        elif rule == "R5":
            explanation = (
                f"{d.get('distinctAccounts')} distinct accounts "
                f"({', '.join(d.get('accounts', []))}) had successful "
                f"logins on {computer} within a {d.get('windowMin')}-minute "
                f"window.")
            recommendation = (RULE_RECOMMENDATIONS["R5"] + " " +
                              R5_FALSE_POSITIVE_NOTE)
            threshold = f"≥ {d.get('threshold')} distinct accounts"
            window = f"W={d.get('windowMin')} min"
        elif rule == "R6":
            related = d.get("relatedCaseKeys") or []
            related_txt = (
                " Related case: " + ", ".join(related)
                if related else "")
            explanation = (
                f"A risk pattern has recurred: {d.get('count')} "
                f"qualifying R1/R2 detection(s) for {account} on "
                f"{computer} within a rolling {d.get('hours')}-hour "
                f"period (first {d.get('firstTs')}, most recent "
                f"{d.get('lastTs')}).{related_txt}")
            recommendation = RULE_RECOMMENDATIONS["R6"]
            threshold = f"≥ {d.get('threshold')} qualifying detections"
            window = f"{d.get('hours')} h rolling"
        else:
            explanation = RULE_EXPLANATIONS.get(rule, "")
            recommendation = RULE_RECOMMENDATIONS.get(rule, "")
            threshold = ""
            window = ""
        out.append({
            "id": rule,
            "name": RULE_NAMES.get(rule, rule),
            "severity": RULE_SEVERITY.get(rule, "Medium"),
            "triggered": True,
            "explanation": explanation,
            "recommendation": recommendation,
            "threshold": threshold,
            "window": window,
            "matchedEventIds": d.get("eventIds",
                                       d.get("relatedEventIds", [])),
            "detail": d,
        })
    return out


def _compute_score(triggered):
    """Rule-based prioritization score (NOT a probability of compromise).

    score = min(100, sum of the weights of the triggered rules)."""
    return min(100, sum(RULE_WEIGHTS.get(r, 0) for r in triggered))


def _analyze_indicators(normalized):
    """Additional security analysis indicators.

    Where the available data supports it, identify potential indicators
    of suspicious activity. These are NOT proof of an attack — only
    potential indicators for human investigation.

    Returns a list of indicator dicts with type, severity, detail, and
    recommendation fields.
    """
    indicators = []
    if not normalized:
        return indicators

    # Group failures by account
    failures_by_account = defaultdict(list)
    successes_by_account = defaultdict(list)
    for e in normalized:
        if e["event"] == "Failure":
            failures_by_account[e["account"]].append(e)
        elif e["event"] == "Success":
            successes_by_account[e["account"]].append(e)

    # Detect potential brute-force: many failures for one account
    for account, fails in failures_by_account.items():
        if len(fails) >= 5:
            src_ips = sorted({f.get("source_ip", "") for f in fails
                             if f.get("source_ip", "")})
            indicators.append({
                "type": "potential_bruteforce",
                "severity": "medium",
                "detail": (f"{len(fails)} failed logon attempts for account "
                           f"'{account}'"),
                "sourceIps": src_ips,
                "recommendation": ("Verify whether this is legitimate failed "
                                   "authentication activity or a potential "
                                   "brute-force attempt."),
            })

    # Detect potential password spraying: one IP targeting many accounts
    failures_by_ip = defaultdict(list)
    for e in normalized:
        if e["event"] == "Failure" and e.get("source_ip", ""):
            failures_by_ip[e["source_ip"]].append(e)
    for ip, fails in failures_by_ip.items():
        accounts = sorted({f["account"] for f in fails})
        if len(accounts) >= 3:
            indicators.append({
                "type": "potential_password_spray",
                "severity": "medium",
                "detail": (f"Source IP {ip} attempted authentication for "
                           f"{len(accounts)} different accounts"),
                "accounts": accounts,
                "recommendation": ("Verify whether this is legitimate "
                                   "authentication activity or a potential "
                                   "password spraying attack."),
            })

    # Detect unusual logon types
    common_logon_types = {"2", "3", "7", "10"}  # Interactive, Network, Unlock, RemoteInteractive
    for e in normalized:
        lt = e.get("logon_type", "")
        if lt and lt not in common_logon_types and e["event"] == "Success":
            indicators.append({
                "type": "unusual_logon_type",
                "severity": "low",
                "detail": (f"Successful logon with unusual type {lt} for "
                           f"account '{e['account']}' on {e['computer']}"),
                "logonType": lt,
                "recommendation": ("Verify whether this logon type is "
                                   "expected for this account and computer."),
            })

    # Detect new/uncommon source IPs (simplified: IP seen with few events)
    all_ips = defaultdict(int)
    for e in normalized:
        if e.get("source_ip", ""):
            all_ips[e["source_ip"]] += 1
    for ip, count in all_ips.items():
        if count <= 2 and ip not in ("", "-", "::1", "127.0.0.1"):
            indicators.append({
                "type": "uncommon_source_ip",
                "severity": "low",
                "detail": (f"Source IP {ip} observed only {count} time(s) "
                           f"in the current data set"),
                "recommendation": ("Verify whether this source IP is "
                                   "expected in your environment."),
            })

    return indicators


# ─── Main entry point ──────────────────────────────────────────────


def detect_cases(events, N=3, W=5, open_time="08:30", close_time="17:30",
                 r4_window=10, r5_threshold=4, r5_window=10,
                 r6_threshold=2, r6_hours=24, prior_matches=None):
    """Run all six rules over a list of event dicts.

    events: list of dicts with keys
        event_id, timestamp, account, computer, event, department_case
    prior_matches: optional list of stored rule-match occurrences
        (dicts with rule_set, account, computer, first_ts, last_ts,
        fingerprint, case_key, matched_event_ids) used by R6.

    Returns a list of case dicts sorted PRIORITY → REVIEW → ROUTINE.
    """
    normalized = _normalize(events)
    normalized.sort(key=lambda x: x["timestamp"])

    # Per account+computer group → R1, R2, R3, R6
    groups = defaultdict(list)
    for e in normalized:
        groups[f"{e['account']}||{e['computer']}"].append(e)

    results = []
    for key, evts in groups.items():
        account, computer = key.split("||", 1)
        results.append(_detect_account_computer(
            evts, account, computer, N, W, open_time, close_time,
            r6_threshold, r6_hours, prior_matches or [],
        ))

    # Cross-entity rules → R4 (account across PCs), R5 (PC across accounts)
    results.extend(_detect_r4(normalized, r4_window))
    results.extend(_detect_r5(normalized, r5_threshold, r5_window))

    results.sort(key=lambda c: (
        PRIORITY_ORDER[c["priority"]], c["account"], c["computer"]))
    return results
