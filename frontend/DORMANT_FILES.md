# Dormant Front-End Files (Phase 2)

Per the product decision (2026-10-16): the new front-end ships **only the pages that
exist in the new design** (Landing, auth, AI Chat home, Assessments, Reports,
Notifications, Profile, Settings, Admin, error pages, dev API bench).

The engagement-workflow pages (Scope, ROE, OSINT, Red Team, Risk, Operations,
Conversation, Report view, Monitoring, old Dashboard) are **unmounted from the router
and excluded from TypeScript compilation** because they reference modules that do not
exist in the repo yet (`src/stores/*`, `src/services/*`). Their files are kept on disk,
untouched, for the phase-2 re-enable (they will be restyled to the new design and fed
from the AI Chat flow).

Excluded (see `tsconfig.json` / `tsconfig.app.json` "exclude"):

- `src/pages/`: DashboardPage, ConversationPage, NewAssessmentPage, OSINTPage,
  OperationsPage, RedTeamPage, RiskAssessmentPage, ScopePage, ReportViewPage, MonitoringPage
- `src/components/`: `osint/`, `redteam/`, `risk/`, `monitoring/`, `chat/`,
  `layout/DashboardLayout.tsx`
- `src/hooks/`: useAuth.ts, useEngagement.ts, useAdmin.ts, useChat.ts,
  useMonitoring.ts, useNotifications.ts, useOSINT.ts, useRedTeam.ts, useReports.ts,
  useRiskAssessment.ts, useScope.ts, useSystemHealth.ts, useUserProfile.ts,
  useVerifyEmail.ts  (legacy hooks from the old front-end; the new pages talk to the
  API layer in `src/api/` directly via TanStack Query)
- `src/utils/encryption.ts` (unused by the new pages; fails modern TS crypto typings)

`src/pages/ResetPasswordPage.tsx` and `src/pages/ContactPage.tsx` remain compiled but
**unmounted** (the new forgot-password flow is two-step in one page; the landing page
carries the contact section). They are kept on disk, untouched.

Vite's production build is unaffected either way: it only bundles modules reachable
from the entry point, and none of the excluded files are imported by mounted routes.
