"""Live verification of Tier-2 Part B (explainable alerts) through the
real admin flow: trigger real blocks, then read the defense alert feed
with an admin 2FA token and assert each alert carries reasons + confidence.
"""
import json
import re
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8000"


def req(method, path, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


results = []
def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}  {detail}")


print("— Trigger real defense blocks —")
# 1. Protocol: TRACE
s, _ = req("TRACE", "/api/v1/public/stats")
check("TRACE blocked", s in (400, 405), f"status={s}")
# 2. Protocol: oversized login body
s, _ = req("POST", "/api/v1/auth/login",
           {"email": "nobody@nowhere-domain.com", "password": "A" * 9000})
check("oversized login blocked", s == 413, f"status={s}")
# 3. Input validation: SQLi payload
s, _ = req("POST", "/api/v1/public/contact",
           {"name": "x' OR '1'='1", "email": "a@b.com",
            "message": "test' UNION SELECT password FROM users --"})
check("SQLi input blocked", s == 400, f"status={s}")
# 4. Rate limit: 65 rapid requests
codes = []
for i in range(65):
    st, _ = req("GET", "/api/v1/public/stats")
    codes.append(st)
check("rate limit fired in burst", 429 in codes,
      f"codes={ {c: codes.count(c) for c in set(codes)} }")

# The burst just consumed this IP's defense rate budget (100/60s) —
# wait for the window to slide before the admin flow runs.
print("  (waiting for the 60s rate window to slide...)")
time.sleep(63)

print("— Admin 2FA —")
s, b = req("POST", "/api/v1/admin/login",
           {"email": "admin@cerberus-ai.com",
            "password": "Admin!zoHBF-1dlBnVVK22"})
check("admin step1", s == 200, f"status={s}")

otp = None
log = open("/tmp/cerberus_api.log").read()
matches = re.findall(
    r"\[CERBERUS DEV\] OTP for admin@cerberus-ai\.com:\s*\n\s*(\d{6})", log)
if matches:
    otp = matches[-1]
check("OTP captured from console", otp is not None, f"otp={otp}")

s, b = req("POST", "/api/v1/admin/verify",
           {"email": "admin@cerberus-ai.com", "otp": otp})
check("admin step2", s == 200, f"status={s}")
tok = b.get("access_token") or b.get("token")
check("admin token issued", bool(tok))

print("— Read the explainable alert feed —")
s, b = req("GET", "/api/v1/defense/alerts", token=tok)
check("alerts endpoint 200", s == 200, f"status={s}")
items = b.get("items", [])
check("alerts recorded", len(items) >= 4, f"count={len(items)}")

by_type = {}
for it in items:
    by_type.setdefault(it.get("attack_type"), []).append(it)

for t in ("protocol_violation", "input_validation", "rate_limit"):
    lst = by_type.get(t, [])
    check(f"alert type {t} present", len(lst) >= 1, f"count={len(lst)}")
    if lst:
        a = lst[0]
        check(f"{t}: has reasons", len(a.get("reasons", [])) >= 1,
              f"reasons={a.get('reasons', [])[:1]}")
        check(f"{t}: has confidence", a.get("confidence") is not None,
              f"confidence={a.get('confidence')}")
        check(f"{t}: has risk_score", a.get("risk_score") is not None,
              f"risk={a.get('risk_score')}")

print("— Dashboard recent_alerts —")
s, b = req("GET", "/api/v1/defense/dashboard", token=tok)
recent = b.get("recent_alerts", [])
check("dashboard 200 + recent alerts", s == 200 and len(recent) >= 1,
      f"status={s} recent={len(recent)}")
if recent:
    check("dashboard alerts carry reasons",
          len(recent[0].get("reasons", [])) >= 1,
          f"reasons={recent[0].get('reasons', [])[:1]}")

print(f"\nEXPLAINABILITY LIVE: {sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
