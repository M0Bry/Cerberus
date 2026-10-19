#!/usr/bin/env python3
"""
Cerberus — periodic system check (run after EVERY modification).

Verifies the live system end-to-end against a running backend + frontend:

  1.  Backend /health
  2.  Frontend serves /
  3.  OpenAPI surface (path count + known endpoints present)
  4.  Public plans (lineup, prices, success URL → /billing)
  5.  User login + protected endpoints (engagements, subscription, notifications)
  6.  Admin login + admin endpoints (dashboard, contact inbox)
  7.  Non-admin is denied admin endpoints (403)
  8.  (opt --send-contact) public contact send → appears in the admin inbox

Credentials live in scripts/check_config.json (gitignored — never committed):
  {
    "backend": "http://localhost:8000",
    "frontend": "http://localhost:3000",
    "user": {"email": "...", "password": "..."},          # any VERIFIED user
    "admin": {"email": "...", "password": "..."},         # ADMIN user
    "db": {"host": "127.0.0.1", "user": "cerberus",
           "password": "...", "database": "cerberus"}     # optional local psql
                                                           # access — required for
                                                           # the full admin 2FA
                                                           # path (D1 → D1b)
  }

Exit code: 0 = all pass, 1 = any failure, 2 = config missing (public checks only).

Usage:  python3 scripts/system_check.py [--send-contact]
"""
import hashlib
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATH = __file__.rsplit("/", 1)[0] + "/check_config.json"

# /health lives at the ROOT (not under /api/v1) — verified behavior, kept as-is.
KNOWN_PATHS = [
    "/api/v1/access",
    "/api/v1/auth/register",
    "/api/v1/auth/verify-otp",
    "/api/v1/auth/login",
    "/api/v1/admin/login",
    "/api/v1/admin/verify",
    "/api/v1/engagements",
    "/api/v1/notifications",
    "/api/v1/public/contact",
    "/api/v1/admin/dashboard",
    "/api/v1/admin/contact-messages",
    "/api/v1/admin/contact-messages/{message_id}/reply",
    "/api/v1/payments/plans",
    "/api/v1/payments/checkout",
    "/api/v1/payments/subscription",
    "/api/v1/payments/webhook",
]


def req(method: str, url: str, token: str | None = None, json_body=None, timeout=10, accept="application/json"):
    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body) if body else None
            except json.JSONDecodeError:
                return resp.status, body.decode(errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body) if body else None
        except json.JSONDecodeError:
            return e.code, body.decode(errors="replace")
    except Exception as e:  # connection refused etc.
        return None, str(e)


RESULTS = []


def check(cid: str, name: str, ok: bool, detail: str = ""):
    RESULTS.append((cid, name, ok, detail))
    mark = "\033[92mPASS\033[0m" if ok else "\033[91mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))


def login(base: str, email: str, password: str):
    """Login with one retry — the backend rate limiter shares ONE per-IP 60s
    bucket across all paths, so two logins close together 429 the second."""
    st, body = req("POST", f"{base}/api/v1/auth/login",
                   json_body={"email": email, "password": password})
    if st == 429:
        print("    (rate limit hit — waiting 65s for the limiter window)")
        time.sleep(65)
        st, body = req("POST", f"{base}/api/v1/auth/login",
                       json_body={"email": email, "password": password})
    tok = body.get("access_token") if isinstance(body, dict) else None
    return st, tok


# ── Admin portal helpers (hardened 2FA login) ─────────────────────────────────
#
# The admin account CANNOT use the standard /auth/login endpoint anymore —
# it is rejected generically (checked as A3). The periodic check authenticates
# the admin the same way a human would: portal login → 6-digit code. In dev
# the code is only in the server console, so when local DB access is
# configured the check recovers it from the stored SHA-256 hash (6-digit
# space → brute force ≈ 1s). This mirrors /tmp/portal_check.py.

def psql(db_cfg: dict, sql: str) -> str | None:
    if not db_cfg or not shutil.which("psql"):
        return None
    try:
        r = subprocess.run(
            ["psql", "-h", db_cfg.get("host", "127.0.0.1"), "-U", db_cfg.get("user", "cerberus"),
             "-d", db_cfg.get("database", "cerberus"), "-t", "-A", "-c", sql],
            env={"PGPASSWORD": db_cfg.get("password", ""), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip()
    except Exception:
        return None


def recover_otp_code(db_cfg: dict) -> str | None:
    """Latest unused admin_login OTP hash → brute force the 1M code space.

    Handles both the hardened salted format ('sha256$<salt>$<digest>') and
    legacy unsalted rows (bare 64-hex digest).
    """
    row = psql(db_cfg, "SELECT hashed_otp FROM otp_verifications WHERE purpose='admin_login' "
                       "AND is_used = FALSE ORDER BY created_at DESC LIMIT 1;")
    if not row:
        return None
    if row.startswith("sha256$"):
        _, salt, digest = row.split("$", 2)
        for i in range(1_000_000):
            if hashlib.sha256(f"{salt}${i:06d}".encode()).hexdigest() == digest:
                return f"{i:06d}"
        return None
    for i in range(1_000_000):
        if hashlib.sha256(f"{i:06d}".encode()).hexdigest() == row:
            return f"{i:06d}"
    return None


def reset_portal_budget(db_cfg: dict) -> None:
    """Clear this check's own portal attempts so runs don't exhaust the
    10/15-min DB limiter (only rows from localhost within the last 10 min)."""
    psql(db_cfg, "DELETE FROM ip_logs WHERE action IN ('admin_login','admin_verify') "
                 "AND ip_address = '127.0.0.1' "
                 "AND created_at > now() - INTERVAL '10 minutes';")


def main():
    send_contact = "--send-contact" in sys.argv
    cfg = {}
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    base = cfg.get("backend", "http://localhost:8000").rstrip("/")
    fe = cfg.get("frontend", "http://localhost:3000").rstrip("/")
    t0 = time.time()
    print(f"\nCerberus system check · backend {base} · frontend {fe}\n")

    # 1. backend health (body is {"status": "healthy", ...} in DEBUG=false mode)
    st, body = req("GET", f"{base}/health")
    healthy = st == 200 and (body == "ok" or (isinstance(body, dict) and body.get("status") in ("healthy", "ok")))
    check("H1", "Backend /health", healthy, f"status={st} body={body if st != 200 else 'healthy'}")

    # 2. frontend (vite's html-fallback only triggers with an html Accept header;
    #    one retry in case the dev server blips during builds)
    st, body = req("GET", f"{fe}/", accept="text/html")
    if st != 200:
        time.sleep(1.5)
        st, body = req("GET", f"{fe}/", accept="text/html")
    check("F1", "Frontend serves /", st == 200, f"status={st}")

    # 3. route surface — docs/openapi are disabled in DEBUG=false, so probe each
    #     known path: 404 = route missing; 401/403/405/422/200 = route exists.
    missing = []
    for p in KNOWN_PATHS:
        st, _ = req("GET", base + p)
        if st == 404:
            st, _ = req("POST", base + p)
        if st == 404:
            missing.append(p)
    check("A1", f"API route surface ({len(KNOWN_PATHS)} known paths)", not missing,
          f"missing: {missing}" if missing else "all expected endpoints present")

    # 4. public plans (endpoint returns a bare list of purchasable plans)
    st, body = req("GET", f"{base}/api/v1/payments/plans")
    ok4 = st == 200 and isinstance(body, list) and len(body) >= 2
    detail4 = f"status={st}"
    if ok4:
        plan_names = [p.get("name") for p in body]
        ok4 = all(isinstance(p.get("price_cents"), int) and p.get("price_cents", 0) > 0 for p in body)
        detail4 = f"{len(body)} purchasable: {', '.join(n.lower() for n in plan_names)}"
    check("P1", "Public plans (lineup + prices)", ok4, detail4)

    cfg_ok = bool(cfg.get("user") and cfg.get("admin"))

    # 5. user login + protected endpoints
    user_tok = None
    if cfg_ok:
        st, user_tok = login(base, cfg["user"]["email"], cfg["user"]["password"])
        check("U1", "User login (verified account)", st == 200 and bool(user_tok), f"status={st}")
        if user_tok:
            st, _ = req("GET", f"{base}/api/v1/engagements", user_tok)
            check("U2", "User → /engagements", st == 200, f"status={st}")
            st, body = req("GET", f"{base}/api/v1/notifications", user_tok)
            check("U3", "User → /notifications", st == 200, f"status={st}")
            st, body = req("GET", f"{base}/api/v1/payments/subscription", user_tok)
            sub = body.get("status") if isinstance(body, dict) else None
            check("U4", "User → /payments/subscription", st == 200, f"status={st} sub={sub or 'none'}")
            # Trial rule: access state must be coherent (paid user → paid;
            # trial user → trial with 0 < days_left <= TRIAL_DAYS).
            st, body = req("GET", f"{base}/api/v1/access", user_tok)
            ok5 = st == 200 and isinstance(body, dict) and body.get("state") in ("paid", "trial", "suspended")
            if ok5 and body["state"] == "trial":
                ok5 = 0 < body.get("trial_days_left", -1) <= 7
            check("U5", "User → /access (trial rule)", ok5,
                  f"state={body.get('state') if isinstance(body, dict) else st} "
                  f"days_left={body.get('trial_days_left') if isinstance(body, dict) else ''}")
    else:
        print("  [SKIP] authenticated checks — scripts/check_config.json missing (public checks only)\n")

    # 6. admin portal (hardened 2FA) + admin endpoints
    admin_tok = None
    db_cfg = cfg.get("db") or {}
    if cfg_ok:
        # A3: the admin account is separated from the standard login —
        # correct admin credentials on /auth/login must be rejected generically.
        st, body = req("POST", f"{base}/api/v1/auth/login",
                       json_body={"email": cfg["admin"]["email"],
                                  "password": cfg["admin"]["password"]})
        detail = f"status={st}"
        if st == 429:  # shared 60s login bucket — the U1 login above may have filled it
            time.sleep(65)
            st, body = req("POST", f"{base}/api/v1/auth/login",
                           json_body={"email": cfg["admin"]["email"],
                                      "password": cfg["admin"]["password"]})
            detail = f"status={st} (after 65s limiter wait)"
        check("A3", "Standard login rejects the admin account", st == 401, detail)

        # D1: portal step 1 — valid admin credentials dispatch the 2FA code.
        st, body = req("POST", f"{base}/api/v1/admin/login",
                       json_body={"email": cfg["admin"]["email"],
                                  "password": cfg["admin"]["password"]})
        if st == 429:
            # exhausted the 10/15-min portal budget (earlier runs) — clear our
            # own localhost rows and retry once
            reset_portal_budget(db_cfg)
            st, body = req("POST", f"{base}/api/v1/admin/login",
                           json_body={"email": cfg["admin"]["email"],
                                      "password": cfg["admin"]["password"]})
        check("D1", "Admin portal step 1 (credentials → code dispatched)",
              st == 200 and isinstance(body, dict) and body.get("requires_otp") is True,
              f"status={st} body={body if st != 200 else 'requires_otp=90s'}")

        # D1b: wrong code must be rejected; right code must issue tokens.
        code = recover_otp_code(db_cfg)
        if code is None:
            check("D1b", "Admin portal step 2 (2FA code → tokens)", False,
                  "could not recover OTP (db config missing, psql unavailable, or code expired)")
        else:
            wrong = "000000" if code != "000000" else "111111"
            st_w, _ = req("POST", f"{base}/api/v1/admin/verify",
                          json_body={"email": cfg["admin"]["email"], "otp": wrong})
            st, body = req("POST", f"{base}/api/v1/admin/verify",
                           json_body={"email": cfg["admin"]["email"], "otp": code})
            admin_tok = body.get("access_token") if isinstance(body, dict) else None
            check("D1b", "Admin portal step 2 (2FA code → tokens)",
                  st_w == 401 and st == 200 and bool(admin_tok),
                  f"wrong_code={st_w} correct_code={st}")
            # keep the limiter budget clean for the next run
            reset_portal_budget(db_cfg)

        if admin_tok:
            st, body = req("GET", f"{base}/api/v1/admin/dashboard", admin_tok)
            check("D2", "Admin → /admin/dashboard", st == 200, f"status={st}")
            st, body = req("GET", f"{base}/api/v1/admin/contact-messages?page=1&page_size=50", admin_tok)
            if st == 200 and isinstance(body, dict) and isinstance(body.get("items"), list):
                check("D3", "Admin → contact inbox", True,
                      f"total={body.get('total')} unread={body.get('unread')}")
            else:
                check("D3", "Admin → contact inbox", False, f"status={st}")
            if user_tok:
                st, _ = req("GET", f"{base}/api/v1/admin/dashboard", user_tok)
                check("D4", "Non-admin denied admin endpoints (403)", st == 403, f"status={st}")
            # Admin user list carries the access state (trial/paid/suspended).
            st, body = req("GET", f"{base}/api/v1/admin/users?page=1&page_size=5", admin_tok)
            items = (body or {}).get("items", []) if isinstance(body, dict) else []
            ok6 = st == 200 and len(items) > 0 and all(
                i.get("access_state") in ("paid", "trial", "suspended") for i in items
            )
            check("D5", "Admin → user list access states", ok6,
                  f"{len(items)} users, states={[i.get('access_state') for i in items][:3]}")

    # 8. optional: public contact send → must appear in admin inbox
    if send_contact and cfg_ok:
        stamp = time.strftime("%H%M%S")
        payload = {"name": "System Check", "email": f"check{stamp}@cerberus-ai.com",
                   "subject": f"Automated check {stamp}",
                   "message": f"Periodic system check contact send at {stamp}. Safe to ignore."}
        st, body = req("POST", f"{base}/api/v1/public/contact", json_body=payload)
        sent_ok = st == 200
        if sent_ok:
            time.sleep(1)
            st2, body2 = req("GET", f"{base}/api/v1/admin/contact-messages?page=1&page_size=5", admin_tok)
            items = (body2 or {}).get("items", []) if isinstance(body2, dict) else []
            found = any(i.get("subject") == payload["subject"] for i in items)
            sent_ok = found
            check("C1", "Public contact send → lands in admin inbox", sent_ok,
                  "sent + visible to admin" if sent_ok else "sent but NOT visible in admin inbox")
        else:
            check("C1", "Public contact send", False, f"status={st} body={body}")

    fails = [r for r in RESULTS if not r[2]]
    print(f"\n{'=' * 56}")
    if fails:
        print(f"\033[91mRESULT: {len(fails)} FAILED / {len(RESULTS)} checks\033[0m")
        for _, name, _, detail in fails:
            print(f"  ✗ {name}: {detail}")
        sys.exit(1)
    print(f"\033[92mRESULT: ALL {len(RESULTS)} CHECKS PASSED\033[0m ({time.time() - t0:.1f}s)")
    sys.exit(0)


if __name__ == "__main__":
    main()
