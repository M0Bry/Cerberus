# Live verification suite (defense stack)

End-to-end scripts that verify the 3-tier defense stack and the
Tier 1/2 hardening parts (A–D) against a RUNNING API + Postgres.
The in-repo `pytest` suite (backend/tests) covers the same logic
hermetically; these scripts are the LIVE evidence trail.

## Prerequisites

- Backend API running on `http://localhost:8000`
  (from `backend/`: `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`).
  With the console email provider, OTP codes are printed to the API terminal.
- Postgres with the `cerberus` database (admin user present).
- For `sqa_validation.js`: the frontend on `http://localhost:3000`,
  Node + `npm i playwright-core@1.64.1` (plus a 1×1 PNG at
  `/tmp/sqa_e2e/photo.png`).

## Order (matters — the alert ring and rate windows are shared)

1. `python defense_hardening_live_test.py`  — Tier 1 A1–A5 (13 checks)
2. `python defense_query_test.py`           — query attacks (4 checks)
3. `python defense_api_test.py`             — defense API endpoints
4. `python defense_flood_test.py`           — flood 429 + recovery
   ⚠ consumes the 100/60s per-IP defense budget — wait ~65s after.
5. `python defense_bruteforce_test.py`      — lockout ladder (wait 60s before)
6. `python defense_explainability_live_test.py` — Tier 2 Part B (24 checks)
   (needs a prior flood/block to populate the alert ring; has a built-in
   63s wait after its own burst)
7. `python part_c_live_test.py`             — Tier 1 Part C (26 checks)
   run the API with `COST_REGISTER_PER_IP=3 COST_RESEND_PER_IP=4`
   for the deterministic caps
8. `python part_d_live_test.py`             — Tier 2 Part D (18 checks)
   run the API with `SESSION_MAX_ACTIVE=2 DEFENSE_USER_RATE_LIMIT=4`
9. `node sqa_validation.js`                 — frontend E2E (12 checks)

`res_seed_db.py` is an idempotent DB seeder (3 plans + admin) — run from any
directory if a fresh database needs bootstrapping; it reads `DATABASE_URL`
from `backend/.env` on its own.
