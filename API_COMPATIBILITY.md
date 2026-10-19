# Frontend ↔ Backend Compatibility Report

**Date:** 2026-10-18 · **Scope:** full audit of every API call in the live (mounted)
frontend against the real FastAPI backend — routes, request bodies, response shapes.
**Method:** static contract audit (frontend `src/api/*` + page-level calls vs.
backend `app/api/v1/endpoints/*` + `app/schemas/*`), plus build + live-route checks.

Legend: ✅ match · 🔧 fixed this pass · ⚠️ backend gap (frontend degrades gracefully) · 📦 phase-2

---

## 1. Live endpoints (mounted UI) — full match list

| # | Endpoint | Frontend caller | Backend | Shape check |
|---|----------|-----------------|---------|-------------|
| 1 | `POST /auth/register` | RegisterPage | auth.py | ✅ {full_name, company_name, job_title, email, phone_number?, company_location?, password, confirm_password} |
| 2 | `POST /auth/verify-otp` | VerifyEmailPage | auth.py | ✅ {email, otp} |
| 3 | `POST /auth/resend-otp` | VerifyEmailPage | auth.py | ✅ {email} |
| 4 | `POST /auth/login` | LoginPage | auth.py | ✅ {email, password} → {access_token, refresh_token, …}; unverified → 4xx "not yet been activated" → UI shows verify banner |
| 5 | `POST /auth/refresh` | axiosInstance interceptor | auth.py | ✅ {refresh_token} |
| 6 | `POST /auth/logout` | Sidebar sign-out | auth.py | ✅ (Bearer) |
| 7 | `GET /users/me` | Login (post-auth), Profile, Settings | users.py | ✅ UserProfileResponse → mapped to frontend `User` (avatar from `profile_image_url`) |
| 8 | `PUT /users/me` | SettingsPage | users.py | ✅ UpdateProfileRequest {full_name?, phone_number?, company_name?, job_title?, company_location?} |
| 9 | `POST /users/me/change-password` | SettingsPage | users.py | ✅ {current_password, new_password, confirm_new_password} |
| 10 | `GET /engagements` | Assessments, Admin, Reports, Chat | engagements.py | ✅ {success, total, page, page_size, items: Engagement[]} |
| 11 | `POST /engagements` | ChatPage (lazy create) | engagements.py | ✅ {project_name, organization_name, objective?, description?} |
| 12 | `GET /engagements/{id}` | ChatPage (`/chat/:id`) | engagements.py | ✅ EngagementResponse |
| 13 | `GET /engagements/{id}/summary` | (api layer) | engagements.py | ✅ |
| 14 | `POST /ai/{id}/message` | ChatPage | ai_conversation.py | ✅ {message, context?} → {message_id, ai_response, follow_up_questions?, context_updated} |
| 15 | `GET /ai/{id}/history` | ChatPage | ai_conversation.py | ✅ {success, engagement_id, messages: [{role, content, timestamp}]} |
| 16 | `GET /ai/{id}/summary` | (api layer) | ai_conversation.py | ✅ |
| 17 | `POST /ai/{id}/confirm-summary` | (api layer) | ai_conversation.py | ✅ |
| 18 | `GET /reports/{eid}` | ReportsPage | reports.py | 🔧 **fixed** — backend `ReportItem` has no `created_at`/`engagement_id` (uses `generated_at`; engagement comes from the list wrapper). Frontend now normalizes both → previously would crash rendering ("Invalid Date") |
| 19 | `GET /reports/{eid}/{rid}` | (api layer) | reports.py | ✅ |
| 20 | `GET /reports/{eid}/{rid}/download` | ReportsPage (blob → PDF) | reports.py | ✅ |
| 21 | `POST /reports/{eid}/generate` | (api layer) | reports.py | ✅ |
| 22 | `GET /notifications` | NotificationsPage | notifications.py | ✅ {total, unread_count, items: [{id, notification_type, title, message, action_url, is_read, created_at}]} |
| 23 | `PUT /notifications/{id}/read` | NotificationsPage (optimistic) | notifications.py | ✅ |
| 24 | `PUT /notifications/read-all` | NotificationsPage | notifications.py | ✅ |
| 25 | `GET /admin/dashboard` | AdminPage KPIs | admin.py | ✅ {total_users, active_users, total_engagements, active_engagements, total_reports, system_health} |
| 26 | `GET /admin/users` | AdminPage | admin.py | ✅ {total, items: AdminUserItem} |
| 27 | `GET /admin/audit-logs` | AdminPage | admin.py | ✅ AuditLogItem {action, severity, description, user_id, ip_address, created_at} |
| 28 | `GET /public/stats` | LandingPage (count-up) | public.py | 🔧 **fixed** — router was written but **never mounted** in `app/api/v1/router.py` → 404 at runtime. Now mounted (landing stats show real values) |
| 29 | `POST /public/contact` | LandingPage contact form | public.py | 🔧 **fixed** (mounted, same as #28) · ⚠️ returns success but **persists nothing** (see §3) |
| 30 | `GET /health` (API root) | AdminPage "Check now" | main.py | ✅ {status, version} (vite dev proxy forwards `/health`) |

**Result: every live call now maps to a real, shape-compatible backend route.**

---

## 2. Fixed in this pass

| Fix | Where | Why |
|-----|-------|-----|
| Mount `public` router | `backend/app/api/v1/router.py` | Landing stats + contact form were calling endpoints that 404'd (files existed, router never included them). 6-line wiring fix, no new logic |
| Reports row normalization | `frontend/src/pages/ReportsPage.tsx` | `ReportItem` has `generated_at`, no `engagement_id`/`created_at` → date crash + unscoped download. Normalized from the list wrapper |
| Audit timestamp guard | `frontend/src/pages/AdminPage.tsx` | Defensive `—` instead of a date crash if a log entry lacks timestamps |

---

## 3. ⚠️ Backend gaps affecting the live UI (frontend degrades gracefully today)

| Gap | Backend state | Frontend behaviour today | Needed for phase 2 |
|-----|---------------|--------------------------|--------------------|
| `POST /auth/forgot-password` + `POST /auth/reset-password` | **not implemented** (email template exists in `backend/templates/`) | Forgot page shows explicit "service not available yet" notice on 404, never fakes step 2 | Implement the 2 endpoints (reuse OTP table + `send_otp_email`) |
| Contact form persistence | `POST /public/contact` returns success, stores nothing | Admin "Contact Messages" = empty state explaining the gap | Add a `ContactMessage` model + store on POST + admin list endpoint |
| Avatar upload | no `POST /users/me/avatar` (field `profile_image_url` exists on user) | Photo shrunk to 128px data-URL in localStorage, flagged in the Settings flash | Add upload endpoint (S3/local) + wire Settings/Register |
| Account deletion | no `DELETE /users/me` | not used in UI (api fn kept) | endpoint + soft-delete |
| Notification preferences | no `/notifications/preferences` | not used in UI (Settings toggles are device-local) | endpoint or drop from api layer |
| **Mail (OTP delivery)** | SMTP code fully written (`app/utils/email.py`, aiosmtplib) but `SMTP_USER/PASSWORD/EMAIL` **empty** | registration/verify works end-to-end in code; the email itself won't arrive without credentials | **Needs your decision + credentials** (see §6) |
| MFA / sessions / login-activity | no endpoints | explicit empty states in Settings | endpoints later |

---

## 4. 📦 Phase-2 (dormant workflow pages) — current contract state

The unmounted pages keep their old API layer (`src/api/{osint,redTeam,risk,scope,monitoring}Api.ts`).
Current match against the backend's real modules:

| Frontend api file | Backend module (mounted) | Status |
|-------------------|--------------------------|--------|
| `osintApi` | `/osint` (start, findings, findings/{id}, knowledge-graph, summary, **POST** export) | partial — frontend also expects `/status`, `/results`, `/dns`, `/ct`, `/github`, `/social`, `/username`, GET export → either extend backend or rewrite the api file when the page returns |
| `redTeamApi` | `/red-team` (**start, complete**, findings, status) | mismatch — frontend expects plan/scan/vulnerabilities/exploits/evidence/rollback → rewrite api file to backend's verbs |
| `riskApi` | `/risk-assessment` (**start, validate**, summary, get) | mismatch — frontend expects matrix/findings/remediation/scores → rewrite |
| `scopeApi` | `/scope` (get, put, **approve**, **assets**) | partial — frontend expects POST create/confirm/export → rewrite |
| `monitoringApi` | `/monitoring` (dashboard, alerts, incidents, blocked-ips, health) | mostly there — missing `alerts/{id}` GET + `alerts/{id}/resolve` → extend backend or simplify UI |

Backend modules with **no frontend api layer yet** (new capabilities to build UI for):
`/attack-planning` (paths, analyze, approve) · `/rules` (generate, sign) · `/documents`
(upload, status) · `/dashboard` (overview, stats) · `/defense` (alerts, dashboard,
threat-intelligence, monitoring) · `/webhooks` (see billing below).

---

## 5. 💳 Billing / subscriptions — current state

- Backend: **stub only** — `webhooks.py` has `POST /stripe` returning `{received: true}`,
  and the webhooks router is **not mounted**. No billing endpoints, no plan field on users,
  no subscription model.
- Frontend: pricing section (landing) is informational; Profile "Subscription plan" card
  falls back to `cerberus_plan` in localStorage, else "Free"; Admin has no billing tab.
- Roadmap (part-by-part, needs your input in §6):
  1. mount `webhooks` router + implement Stripe signature verification
  2. add `Plan`/`Subscription` models + `GET/PUT /billing/subscription`, `GET /billing/checkout` (Stripe Checkout session)
  3. add `plan` to `UserProfileResponse` → Profile card + admin user table become real
  4. plan limits in the engagement-creation flow (assessments/month, scopes, retention)

---

## 6. ✅ Verification summary (this pass)

- Repo synced from GitHub: `origin/main` @ `21ef614` — no remote commits I was missing
- `tsc && vite build` — **green**
- All 20 app routes serve 200 (dev server, SPA fallback included)
- Mounted pages: zero old-identity classes; CSS order = new design wins
- First-load screen = new red loader (no white/blue flash — dark body + color-scheme)
- Every live API call verified against a real backend route + schema (table §1)

## 7. ❓ Open decisions (your input needed)

1. **Mail** — keep SMTP (then we need: provider/host, user, password/app-token, from-email) or switch to a transactional API (Resend / SendGrid / Mailgun)? For local dev, Mailpit or a "log codes to console" dev mode would let us test without real mail.
2. **Payments** — is Stripe the chosen provider, and do you have a Stripe account (test mode is fine to start)? Or another provider (PayPal, local gateway)? The webhook stub suggests Stripe was the intent.
3. **Test backend** — the repo has a root `docker-compose.yml` (Postgres + Redis) and `backend/.env.example`. Once a mail dev-mode is chosen (e.g. log-to-console / Mailpit), I can bring the stack up and run a live end-to-end smoke: register → OTP → login → AI chat → report. Should I set that up in this environment, or will you run the stack locally?
