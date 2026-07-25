/**
 * Routes — Route path constants.
 */

export const ROUTES = {
  HOME: "/",
  LOGIN: "/login",
  REGISTER: "/register",
  VERIFY_EMAIL: "/verify-email",
  FORGOT_PASSWORD: "/forgot-password",
  DASHBOARD: "/dashboard",
  CHAT: "/chat",
  CHAT_WITH_ID: (id: string) => `/chat/${id}`,
  SCOPE: (id: string) => `/scope/${id}`,
  OSINT: (id: string) => `/osint/${id}`,
  REDTEAM: (id: string) => `/redteam/${id}`,
  RISK: (id: string) => `/risk/${id}`,
  REPORTS: "/reports",
  REPORT_VIEW: (id: string) => `/reports/${id}`,
  PROFILE: "/profile",
  SETTINGS: "/settings",
  NOTIFICATIONS: "/notifications",
  ADMIN: "/admin",
  MONITORING: "/monitoring",
  PRIVACY: "/privacy",
  TERMS: "/terms",
  CONTACT: "/contact",
} as const;
