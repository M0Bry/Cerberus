import json, re, time, urllib.request, urllib.error

BASE = "http://localhost:8000"
LOG = "/tmp/cerberus_api.log"

def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}

ok = fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  PASS  {name} {extra}")
    else:
        fail += 1; print(f"  FAIL  {name} {extra}")

# ── 1. Admin 2FA login ──
s, b = req("POST", "/api/v1/admin/login", {"email": "admin@cerberus-ai.com", "password": "Admin!zoHBF-1dlBnVVK22"})
check("admin login step1", s == 200 and b.get("requires_otp"), f"-> {s}")

time.sleep(1.5)
otp = None
with open(LOG) as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "OTP for admin@cerberus-ai.com" in line:
        m = re.search(r"(\d{6})", lines[i + 1])
        if m:
            otp = m.group(1)  # last one wins
check("OTP captured from console", otp is not None, f"otp={otp}")

s, b = req("POST", "/api/v1/admin/verify", {"email": "admin@cerberus-ai.com", "otp": otp})
check("admin verify step2", s == 200, f"-> {s} {json.dumps(b)[:120]}")
admin_token = b.get("access_token") or b.get("token") or (b.get("data") or {}).get("access_token")
check("admin JWT issued", bool(admin_token))

# ── 2. Regular user token ──
s, b = req("POST", "/api/v1/auth/login", {"email": "audit_1792373204@cerberus-test.com", "password": "Audit#Pass123"})
user_token = b.get("access_token") or b.get("token") or (b.get("data") or {}).get("access_token")
check("regular user login", s == 200 and bool(user_token), f"-> {s}")

# ── 3. Defense API access control ──
s, b = req("GET", "/api/v1/defense/dashboard")
check("defense dashboard anonymous -> 401", s == 401, f"-> {s}")

s, b = req("GET", "/api/v1/defense/dashboard", token=user_token)
check("defense dashboard regular user -> 403", s == 403, f"-> {s}")

s, b = req("GET", "/api/v1/defense/dashboard", token=admin_token)
check("defense dashboard admin -> 200", s == 200, f"-> {s}")
if s == 200:
    d = b.get("data", b)
    keys = list(d.keys())
    print("         dashboard keys:", keys[:12])
    metrics = d.get("metrics") or d
    print("         requests_inspected:", metrics.get("requests_inspected"), "| threats_blocked:", metrics.get("threats_blocked"))

s, b = req("GET", "/api/v1/defense/metrics", token=admin_token)
check("defense metrics admin -> 200", s == 200, f"-> {s}")

s, b = req("GET", "/api/v1/defense/alerts", token=admin_token)
check("defense alerts admin -> 200", s == 200, f"-> {s}")

s, b = req("GET", "/api/v1/defense/monitoring", token=admin_token)
check("defense monitoring admin -> 200", s == 200, f"-> {s}")

s, b = req("GET", "/api/v1/defense/blocked-ips", token=admin_token)
check("defense blocked-ips admin -> 200", s == 200, f"-> {s} {json.dumps(b)[:150]}")

# regular user blocked from the sensitive ones too
s, b = req("POST", "/api/v1/defense/block-ip", {"ip": "203.0.113.66", "duration_seconds": 60, "reason": "test"}, token=user_token)
check("block-ip as regular user -> 403", s == 403, f"-> {s}")

s, b = req("POST", "/api/v1/defense/block-ip", {"ip": "203.0.113.66", "duration_seconds": 60, "reason": "defense integration test"}, token=admin_token)
check("block-ip as admin -> 201", s in (200, 201), f"-> {s} {json.dumps(b)[:150]}")

s, b = req("POST", "/api/v1/defense/unblock-ip", {"ip": "203.0.113.66"}, token=admin_token)
check("unblock-ip as admin -> 200", s in (200, 201), f"-> {s}")

print(f"\nDEFENSE API: {ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
