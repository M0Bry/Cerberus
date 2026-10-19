# Tier-3 Response — Development Brief (for the Tier-3 AI Agent)

**Status:** This is a work handoff. Tier 1 (prevention) and Tier 2
(detection) are owned by a separate agent — **do not modify** the files
listed under "File ownership" below unless a change is strictly
impossible otherwise (document it in your commit message if so).

**Current commit baseline:** `60020e6` (Tier-2 hardening complete).
**Overall Tier-3 assessment: 5/10** — the tier runs, but its output
(virtual patches) has no enforcement path, and its LLM output is not
validated or safety-checked before use.

---

## 1. What Tier 3 does today (verified)

- `app/ai_engine/defense/tier3_generative.py` — escalates from Tier-1/2
  block events (via `defense_middleware._maybe_escalate_tier3`, 30s/IP
  cooldown), calls an LLM with `DEFENSE_VIRTUAL_PATCH_SYSTEM_PROMPT`
  (`app/ai/prompts/system_prompt.py`) to generate a **virtual patch**
  (WAF rule JSON: `rule_type` waf_rule/rate_limit/ip_block/header_check,
  `pattern`, `action`, `ttl_hours`, `confidence`).
- **Mock mode** when no API key is configured (`tier3_mock_mode_enabled`):
  returns a canned patch. Both modes were verified live (log:
  `tier3_analysis_started`, `incident_recorded backend=memory`).
- `app/core/auto_mitigation.py`, `graduated_response.py`,
  `feedback_loop.py`, `explainability.py` — pipeline pieces that exist
  but are only partially wired.
- Incidents: `AbuseDetector.record_incident()` → in-memory/Redis store →
  `GET /api/v1/defense/incidents`.

## 2. Gaps to close (in priority order)

### G1 — Virtual patches are generated but NEVER enforced  (the big one)
A generated patch sits in a Redis/memory store and blocks nothing.
Build a **live patch rule engine**:

- Store: active patches with `id, rule_type, pattern, action, ttl,
  created_at, hits, source_incident, status` (Redis-first + in-memory
  fallback, same pattern as the rest of the defense stack).
- Enforcement hook: inside `DefenseMiddleware.dispatch`, **after** the
  static input-validation stage, evaluate the request against active
  patches (waf_rule → regex over the request variants produced by
  `PayloadDecoder.decode_all` — reuse it, never single-decode;
  ip_block → IP check; rate_limit → per-IP counter; header_check →
  header match). On hit: 403 + `record_security_alert(
  attack_type="virtual_patch", reasons=[f"Patch {id} '{rule_name}' hit"],
  confidence=<patch.confidence>)` + increment patch `hits`.
- **Safety gates before a patch goes active** (non-negotiable):
  1. LLM output must be strict-JSON and match the schema
     (`rule_type` enum, `action` enum, `ttl_hours` 1–168, `confidence`
     0–1). Reject (log + incident) on any violation.
  2. `pattern` must compile as a regex (bounded: ≤ 200 chars), be tested
     for ReDoS by running it with a timeout against a benign sample AND
     the original attack sample (must match the attack, must NOT match
     the benign sample — e.g. a normal login JSON).
  3. Patches with `confidence < 0.7` go to **shadow mode**: evaluated
     and logged as alerts but not blocking, until an admin promotes
     them (admin endpoint) or they expire.
- Admin API (extend `/api/v1/defense/`): `GET /virtual-patches`
  (active + shadow + expired, with hit counts), `POST
  /virtual-patches/{id}/promote`, `POST /virtual-patches/{id}/revoke`.
  Admin-only like the rest of the defense surface.

### G2 — Escalation cooldown is flat
`_maybe_escalate_tier3` uses a 30s/IP cooldown regardless of severity.
Make it severity-aware (e.g. `ip_blocked`/hard-block events escalate
immediately; `rate_limit` keeps the cooldown). Keep the "one analysis
per IP per window" property.

### G3 — No patch lifecycle management
Patches should: expire by TTL (enforcement must check `ttl`); a patch
with `hits > N` (e.g. 50) within its TTL auto-escalates to a hard IP
block for the source IP (the attack is continuing — patch alone is
insufficient); a patch that never hits within half its TTL is marked
`expired_inert` for reporting.

### G4 — Incidents never reach the admin portal
The user's product spec: security-relevant events must surface to the
admin (their Notifications system exists — `app/services/notification
_service` / `/api/v1/notifications`). Wire: hard IP block, virtual-patch
activation (non-shadow), and repeated behavioral anomalies → a
notification for the admin user(s) (role ADMIN), with the alert's
reasons. Do NOT create a new notification channel — use the existing
one.

### G5 — LLM provider coupling
`DEFENSE_LLM_PROVIDER=openai` with a direct call. If the provider
times out/errors, ensure the tier degrades to the mock-mode canned
patch + incident (verify the current try/except actually covers
provider timeouts, not just key-missing). Add a response timeout
(≤ 20s) so a hung LLM can never stall the escalation path.

## 3. Hard constraints

1. **Graceful degradation everywhere**: no Redis → in-memory; no LLM key
   → mock mode; LLM error → incident + canned patch. The system must
   start and run with zero external services (this sandbox proves that
   expectation daily).
2. **No public API contract breaks.** New endpoints are additive.
   Existing `/api/v1/defense/*` responses keep their fields (new
   optional fields are fine — see how `SecurityAlertItem` gained
   `reasons/risk_score/confidence`).
3. **Normal traffic must stay green** — the full gate battery is the
   acceptance bar (below).
4. Follow the existing alert convention:
   `record_security_alert(...)` from
   `app/api/v1/middleware/defense_middleware.py` for every block/detect
   event you add, with reasons + confidence.
5. Test isolation: anything new that keeps in-memory state must be
   cleared by `reset_defense_state()` (same file) so pytest stays
   hermetic.

## 4. File ownership (avoid collisions with the Tier-1/2 agent)

**Yours:** `app/ai_engine/defense/tier3_generative.py`,
`app/core/auto_mitigation.py`, `app/core/graduated_response.py`,
`app/core/feedback_loop.py`, `app/core/model_registry.py`,
`app/core/notifier.py`, `app/core/whitelist_manager.py`, new patch-store
module (suggest `app/core/virtual_patch.py`), new
`app/api/v1/endpoints` routes for virtual patches (add to the existing
defense router), `app/prompts` Tier-3 prompt sections.

**Theirs (do not edit):** `app/api/v1/middleware/defense_middleware.py`
*except* the two documented hook points (G1 enforcement hook after the
input-validation stage; G2 cooldown call site),
`app/ai_engine/defense/tier2_behavioral.py`,
`app/core/{input_validator,payload_decoder,rate_limiter,ip_resolver,
abuse_detector,anomaly_detection}.py`, `app/services/auth_service.py`,
`app/schemas/defense.py` (additions to the alert/patch schemas are
allowed — coordinate field names).

If you must touch a "theirs" file, keep the diff minimal and call it
out in the commit.

## 5. Acceptance criteria (all must pass)

1. `python3 -m pytest tests/ -q` → all green (existing + yours).
2. New tests covering at minimum:
   - a generated (mock) patch that matches its attack sample blocks a
     replay of that attack (403) and does NOT block a benign request
     (200);
   - an invalid LLM output (bad JSON / bad regex / ReDoS pattern /
     pattern that matches benign traffic) is rejected and recorded as
     an incident, never activated;
   - shadow-mode patch logs an alert but returns 200;
   - promote + revoke admin endpoints work (admin 200/201, user 403);
   - TTL expiry stops enforcement;
   - high-hit patch triggers the auto IP-block escalation.
3. Live battery (scripts in `/home/user/pwtest/`):
   - `defense_query_test.py` (4/4), `defense_flood_test.py`,
     `defense_bruteforce_test.py`, `defense_hardening_live_test.py`
     (13/13), `defense_api_test.py` (15/15),
     `defense_explainability_live_test.py` (24/24).
   - `python3 scripts/system_check.py` → 16/16.
   - `node /home/user/pwtest/sqa_validation.js` → 12/12.
4. Commit message documents which of G1–G5 are closed and any
   constraint that forced a deviation.

## 6. Environment notes (so you don't lose an afternoon)

- Backend runs from `/home/user/Cerberus/backend`:
  `uvicorn app.main:app --host 0.0.0.0 --port 8000` (dev `.env` already
  present; `DEBUG=true` auto-creates tables).
- **This sandbox wipes non-workspace state between turns** (pip
  packages, postgres, node_modules, git identity). If imports fail:
  `pip install -r requirements.txt` (backend dir), and
  `pip install "pytest-asyncio==0.25.0" "pytest-cov==6.1.1"
  "factory-boy==3.3.3" "faker==36.1.0"` for tests. If Postgres is down:
  `sudo pg_ctlcluster 17 main start`; roles `cerberus`/
  `cerberus_secret` (db `cerberus`) and `cerberus_test`/
  `cerberus_test_secret` (db `cerberus_test`).
- Admin 2FA for live tests: `POST /api/v1/admin/login`
  (`admin@cerberus-ai.com`, password in `scripts/check_config.json` —
  gitignored), the OTP is printed to the API console log
  (`/tmp/cerberus_api.log`, line `[CERBERUS DEV] OTP for ...`), then
  `POST /api/v1/admin/verify`.
- Rate windows are 60s — wait out the window between burst tests (the
  100/60s per-IP defense limit shares the budget with your test
  traffic).
- Test emails: pydantic `EmailStr` rejects reserved TLDs (`.test`,
  `.example`, `.invalid`) — use e.g. `nowhere-domain.com`.
