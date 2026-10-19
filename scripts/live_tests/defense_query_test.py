import json, urllib.parse, urllib.request, urllib.error

BASE = "http://localhost:8000"

def req(method, path, query="", body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path + query, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
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

q = urllib.parse.quote

# B6. SQLi in query param (URL-encoded as a real client sends)
s, b = req("GET", "/api/v1/public/contact", "?name=" + q("admin' or '1'='1"))
check("SQLi query param blocked", s == 400, f"-> {s}")

# B7. XSS in query param
s, b = req("GET", "/api/v1/public/contact", "?q=" + q("<script>alert(1)</script>"))
check("XSS query param blocked", s == 400, f"-> {s}")

# B10. Path traversal in query
s, b = req("GET", "/api/v1/public/contact", "?file=" + q("../../etc/passwd"))
check("path traversal query blocked", s == 400, f"-> {s}")

# B11. legit query still passes (sanity)
s, b = req("GET", "/api/v1/public/contact", "?name=" + q("John Smith") + "&topic=" + q("penetration testing"))
check("legit query NOT blocked", s in (200, 404, 405), f"-> {s}")

print(f"\nQUERY ATTACKS: {ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
