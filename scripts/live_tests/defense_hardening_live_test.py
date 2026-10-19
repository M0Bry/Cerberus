"""Live verification of Tier-1 hardening against the running API."""
import httpx
import json

BASE = "http://localhost:8000"

def jbody(r):
    try:
        return r.json()
    except Exception:
        return {}

results = []
def check(name, cond, detail=""):
    results.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}  {detail}")

client = httpx.Client(timeout=30)

print("— A2: HTTP method allowlist —")
r = client.request("TRACE", f"{BASE}/api/v1/public/stats")
check("TRACE rejected 405", r.status_code == 405, f"got {r.status_code}")
check("Allow header present", "Allow" in r.headers, r.headers.get("Allow", "")[:50])
r = client.request("FOO", f"{BASE}/api/v1/public/stats")
# uvicorn/h11 rejects non-standard method tokens at the protocol layer
# (400) BEFORE the app; the middleware 405 is defense-in-depth for
# valid-but-forbidden methods (TRACE). Either rejection is correct.
check("custom verb FOO rejected (400 protocol / 405 middleware)",
      r.status_code in (400, 405), f"got {r.status_code}")

print("— A3: body size caps —")
r = client.post(f"{BASE}/api/v1/auth/login",
                json={"email": "nobody@nowhere-domain.com", "password": "A" * 9000})
check("oversized login (9KB) rejected 413", r.status_code == 413, f"got {r.status_code}")
r = client.post(f"{BASE}/api/v1/public/contact",
                data=json.dumps({"name": "X", "email": "a@b.com", "message": "z" * 300000}),
                headers={"Content-Type": "application/json"})
check("oversized contact (300KB) rejected 413", r.status_code == 413, f"got {r.status_code}")
r = client.request("POST", f"{BASE}/api/v1/public/stats", headers={"Expect": "100-continue"})
check("Expect:100-continue rejected 411", r.status_code == 411, f"got {r.status_code}")

print("— A1: XFF anti-spoofing (TRUSTED_PROXY_CIDRS empty → XFF ignored) —")
# A normal request with a spoofed XFF must behave exactly like one without.
r1 = client.get(f"{BASE}/api/v1/public/stats")
r2 = client.get(f"{BASE}/api/v1/public/stats", headers={"X-Forwarded-For": "8.8.8.8, 1.1.1.1"})
check("spoofed XFF changes nothing (same status)", r1.status_code == r2.status_code == 200,
      f"clean={r1.status_code} spoofed={r2.status_code}")

print("— A4/A5: enumeration + timing (live shape checks) —")
# verify-otp with unknown email → generic 400 (NOT 404 'User not found')
r = client.post(f"{BASE}/api/v1/auth/verify-otp",
                json={"email": "ghost@nowhere-domain.com", "otp": "123456"})
check("verify-otp unknown email -> 400 (not 404)", r.status_code == 400,
      f"got {r.status_code} {json.dumps(jbody(r))[:60]}")
# resend-otp with unknown email -> 200 uniform shape (NOT 404)
r = client.post(f"{BASE}/api/v1/auth/resend-otp",
                json={"email": "ghost@nowhere-domain.com"})
check("resend-otp unknown email -> 200 uniform (not 404)", r.status_code == 200,
      f"got {r.status_code} cooldown={jbody(r).get('cooldown_seconds')}")
# login with unknown email -> 401 (unchanged, and now timing-equalized)
import time
r = client.post(f"{BASE}/api/v1/auth/login",
                json={"email": "ghost@nowhere-domain.com", "password": "Whatever123"})
check("login unknown email -> 401", r.status_code == 401, f"got {r.status_code}")

print("— regression: normal traffic still passes —")
r = client.get(f"{BASE}/health")
check("GET /health 200", r.status_code == 200, f"got {r.status_code}")
r = client.get(f"{BASE}/api/v1/public/stats")
check("GET /public/stats 200", r.status_code == 200, f"got {r.status_code}")
r = client.get(f"{BASE}/api/v1/payments/plans")
check("GET /payments/plans 200", r.status_code == 200, f"got {r.status_code}")

client.close()
passed = sum(results)
print(f"\nLIVE HARDENING: {passed}/{len(results)} checks passed")
raise SystemExit(0 if passed == len(results) else 1)
