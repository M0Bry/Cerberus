/**
 * Routes — Route path constants.
 *
 * New front-end (current): Landing, auth pages, AI Chat (home), Assessments,
 * Reports, Notifications, Profile, Settings, Admin, error pages, dev API bench.
 *
 * The engagement-workflow routes (scope/osint/redteam/risk/operations/…) are
 * DORMANT — kept here for the phase-2 re-enable; their pages are excluded
 * from compilation (see tsconfig.json "exclude" + DORMANT_FILES.md).
 */

export const ROUTES = {
  HOME: "/",
  LOGIN: "/login",
  REGISTER: "/register",
  VERIFY_EMAIL: "/verify-email",
  FORGOT_PASSWORD: "/forgot-password",
  CHAT: "/chat",
  CHAT_WITH_ID: (id: string) => `/chat/${id}`,
  ASSESSMENTS: "/assessments",
  REPORTS: "/reports",
  NOTIFICATIONS: "/notifications",
  PROFILE: "/profile",
  SETTINGS: "/settings",
  ADMIN: "/admin",
  UNAUTHORIZED: "/unauthorized",
  SERVER_ERROR: "/server-error",
  MAINTENANCE: "/maintenance",
  PRIVACY: "/privacy",
  TERMS: "/terms",
  COMPLIANCE: "/compliance",
  CONTACT: "/contact",
  DEV_API: "/dev/api",

  // ── Dormant (phase 2) ─────────────────────────────────────────
  DASHBOARD: "/dashboard",
  CHAT_OLD: "/chat",
  CONVERSATION: (id: string) => `/conversation/${id}`,
  NEW_ASSESSMENT: "/assessments/new",
  SCOPE: (id: string) => `/scope/${id}`,
  OSINT: (id: string) => `/osint/${id}`,
  REDTEAM: (id: string) => `/redteam/${id}`,
  RISK: (id: string) => `/risk/${id}`,
  OPERATIONS: (id: string) => `/operations/${id}`,
  REPORT_VIEW: (id: string) => `/reports/${id}`,
  MONITORING: "/monitoring",
} as const;
