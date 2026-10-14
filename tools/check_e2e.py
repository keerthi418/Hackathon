"""End-to-end HTTP test against the running app."""
import json
import sys
import urllib.request
import urllib.error
from http.cookiejar import CookieJar

BASE = "http://127.0.0.1:5000"
cj = CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj))


def call(method, path, payload=None, is_json=True, raw=False):
    url = BASE + path
    data = None
    headers = {}
    if payload is not None:
        if is_json:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        else:
            data = payload
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with opener.open(req, timeout=10) as res:
            body = res.read().decode()
            return res.status, (body if raw else json.loads(body))
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def main():
    # 1. login
    st, d = call("POST", "/login",
                 {"username": "admin", "password": "LabTrace@2025"})
    print("login:", st, "ok=", d.get("ok"))
    assert st == 200 and d.get("ok")

    # 2. load demo CSV
    st, d = call("POST", "/api/load-demo")
    print("load-demo:", st, d)
    assert st == 200

    # 3. dashboard metrics + cases
    st, d = call("GET", "/api/dashboard")
    m = d["metrics"]
    print("metrics:", m)
    print("cases:", len(d["cases"]))
    for c in d["cases"]:
        print("  ", c["priority"], "|", c["case_key"],
              "| rules=", c["rules"], "| sev=", c["severity"],
              "| score=", c["score"])
    assert "openCases" in m and "highPriority" in m
    assert "recentEvents" in m and "toReview" in m

    # 4. rule filter (server-side)
    st, r1 = call("GET", "/api/dashboard?rule=R1")
    print("R1 filter cases:", len(r1["cases"]))
    for c in r1["cases"]:
        assert "R1" in c["rules"]

    # 5. case detail with rule explanations
    r1case = [c for c in d["cases"] if "R1" in c["rules"]][0]
    st, detail = call("GET", f"/api/cases/{r1case['id']}")
    print("case detail keys:", sorted(detail.keys()))
    print("rule_details count:", len(detail["rule_details"]))
    for rd in detail["rule_details"]:
        print("   ", rd["id"], "|", rd["name"])
        print("      expl:", rd["explanation"][:110])
        print("      rec :", rd["recommendation"][:70])
        print("      thr :", rd["threshold"], "| win:", rd["window"])
        print("      matched:", rd["matchedEventIds"])
    assert detail["rule_details"], "no rule explanations returned"
    rd = detail["rule_details"][0]
    for key in ("id", "name", "severity", "explanation",
                "recommendation", "threshold", "window",
                "matchedEventIds"):
        assert key in rd, f"missing {key} in rule detail"

    # 6. review workflow: confirm -> dismiss -> escalate
    cid = r1case["id"]
    st, d = call("POST", f"/api/cases/{cid}/action",
                 {"action": "confirm"})
    print("confirm:", st, d)
    st, d = call("POST", f"/api/cases/{cid}/action",
                 {"action": "dismiss"})
    print("dismiss:", st, d)
    st, d = call("POST", f"/api/cases/{cid}/action",
                 {"action": "escalate"})
    print("escalate:", st, d)
    assert st == 200 and d.get("priority") == "PRIORITY"

    # 7. audit log
    st, audit = call("GET", "/api/audit")
    print("audit entries:", len(audit))
    assert st == 200 and isinstance(audit, list)

    # 8. monitor endpoints still work
    for ep in ("/api/monitor/overview", "/api/monitor/alerts",
               "/api/monitor/banner", "/api/monitor/collectors",
               "/api/monitor/server"):
        st, _ = call("GET", ep)
        print("monitor", ep, "->", st)
        assert st == 200

    print("\nALL END-TO-END CHECKS PASSED")


if __name__ == "__main__":
    main()
