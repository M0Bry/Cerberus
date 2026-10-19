import json, time, urllib.request, urllib.error

BASE = "http://localhost:8000"

def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=15) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)

t0 = time.time()
codes = {}
for i in range(115):
    s, h = get("/api/v1/public/stats")  # any non-excluded GET
    codes[s] = codes.get(s, 0) + 1
dt = time.time() - t0

print(f"115 requests in {dt:.1f}s -> {codes}")
total_429 = codes.get(429, 0)
print("flood test:", "PASS" if total_429 > 0 and sum(codes.values()) == 115 else "CHECK")

# api still responsive after flood
s, h = get("/health")
print("post-flood health:", s, "-> PASS" if s == 200 else "-> FAIL")
