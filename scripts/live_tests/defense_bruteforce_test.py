import json, time, urllib.request, urllib.error

BASE = "http://localhost:8000"

def login(email, password):
    data = json.dumps({"email": email, "password": password}).encode()
    h = {"Content-Type": "application/json"}
    r = urllib.request.Request(BASE + "/api/v1/auth/login", data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            body = json.loads(resp.read() or b"{}")
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}

email = "audit_1792373204@cerberus-test.com"
good_pw = "Audit#Pass123"

print("— Phase 1: 5 failed logins (wrong password) —")
for i in range(1, 6):
    s, b = login(email, "Wrong#Pass999")
    msg = (b.get("error") or {}).get("message", "") or b.get("detail", "")
    print(f"  attempt {i}: {s}  {msg[:60]}")

print("— Phase 2: CORRECT password, but IP is now flagged abusive —")
time.sleep(0.5)
s, b = login(email, good_pw)
msg = (b.get("error") or {}).get("message", "") or b.get("detail", "")
print(f"  valid login: {s}  {msg[:70]}")
abuse_blocked = (s == 403)

print("— Phase 3: keep hammering until hard block (10 total failures) —")
for i in range(4):
    s, b = login(email, "Wrong#Pass999")
    msg = (b.get("error") or {}).get("message", "") or b.get("detail", "")
    print(f"  blocked-attempt {i+1}: {s}  {msg[:60]}")

print("— Phase 4: after hard block, even GETs should be 403 —")
try:
    with urllib.request.urlopen(BASE + "/api/v1/public/stats", timeout=15) as r:
        s2 = r.status
except urllib.error.HTTPError as e:
    s2 = e.code
print(f"  GET /public/stats: {s2}")
hard_blocked = (s2 == 403)

print()
print("BRUTE FORCE TEST:", "PASS" if (abuse_blocked and hard_blocked) else "CHECK (see codes above)")
raise SystemExit(0 if (abuse_blocked and hard_blocked) else 1)
