"""LogLens Rule Engine - R1 Failure Burst → Success, R2 After-Hours Success"""
from datetime import datetime, timedelta
from collections import defaultdict


def parse_ts(s):
    try:
        return datetime.strptime(str(s).strip(), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def format_ts(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else None


def is_outside_hours(dt, open_str="08:30", close_str="17:30"):
    oh, om = map(int, open_str.split(":"))
    ch, cm = map(int, close_str.split(":"))
    mins = dt.hour * 60 + dt.minute
    return mins < (oh * 60 + om) or mins >= (ch * 60 + cm)


def detect_cases(events, N=3, W=5, open_time="08:30", close_time="17:30"):
    """
    events: list of dicts with keys:
      event_id, timestamp, account, computer, event, department_case
    """
    normalized = []
    for e in events:
        ts = e["timestamp"] if isinstance(e.get("timestamp"), datetime) else parse_ts(e.get("timestamp"))
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
            "department_case": str(e.get("department_case", e.get("department", ""))),
        })

    normalized.sort(key=lambda x: x["timestamp"])

    groups = defaultdict(list)
    for e in normalized:
        key = f"{e['account']}||{e['computer']}"
        groups[key].append(e)

    results = []
    for key, evts in groups.items():
        account, computer = key.split("||", 1)
        failures = []
        r1 = r2 = False
        r1_detail = r2_detail = None
        matched_ids = set()

        for e in evts:
            if e["event"] == "Failure":
                failures.append(e)
                continue

            # R1: look back W minutes for ≥ N failures
            window_start = e["timestamp"] - timedelta(minutes=W)
            recent = [f for f in failures if window_start <= f["timestamp"] < e["timestamp"]]
            if len(recent) >= N:
                r1 = True
                r1_detail = {
                    "failCount": len(recent),
                    "windowMin": W,
                    "from": format_ts(recent[0]["timestamp"]),
                    "to": format_ts(e["timestamp"]),
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
                }
                matched_ids.add(e["event_id"])

        if r1 and r2:
            priority = "PRIORITY"
            reason = f"{r1_detail['failCount']} failures → success within {W} min AND after-hours login"
            human_check = "Was this after-hours login allowed? Verify whether the account holder or an authorized person was expected."
        elif r1:
            priority = "REVIEW"
            reason = f"{r1_detail['failCount']} failures → success within {W} min window"
            human_check = "Was this a scheduled guest / shared session or legitimate password retry?"
        elif r2:
            priority = "REVIEW"
            reason = f"Successful login outside lab hours ({open_time}–{close_time})"
            human_check = "Was after-hours access pre-approved for this account / machine?"
        else:
            priority = "ROUTINE"
            total_fails = len(failures)
            if total_fails == 0:
                reason = "No failures observed"
            elif total_fails < N:
                reason = f"{total_fails} failure(s) — below threshold N={N}"
            else:
                reason = f"{total_fails} failure(s) spread outside window W={W} min (no burst before success)"
            human_check = None

        results.append({
            "case_key": key.replace("||", " @ "),
            "account": account,
            "computer": computer,
            "department": evts[0]["department_case"] if evts else "",
            "priority": priority,
            "r1": r1,
            "r2": r2,
            "reason": reason,
            "human_check": human_check,
            "event_count": len(evts),
            "matched_event_ids": list(matched_ids),
            "r1_detail": r1_detail,
            "r2_detail": r2_detail,
            "events": [
                {
                    "event_id": e["event_id"],
                    "timestamp": format_ts(e["timestamp"]),
                    "event": e["event"],
                }
                for e in evts
            ],
            "status": "open",
        })

    order = {"PRIORITY": 0, "REVIEW": 1, "ROUTINE": 2}
    results.sort(key=lambda c: (order[c["priority"]], c["account"]))
    return results
