/**
 * AppRouter — routes for the new front-end (17 pages from the design).
 *
 * Public:  landing, register, verify-email, login, forgot-password,
 *          privacy, terms, compliance, dev api bench, system pages
 * App:     /chat (home), /assessments, /reports, /notifications,
 *          /profile, /settings — all inside AppShell (sidebar layout)
 * Admin:   /admin/* — role check happens inside AdminPage (new design shows
 *          the denied panel within the app shell, like admin.html)
 *
 * The old engagement-workflow routes (/scope, /osint, /redteam, /risk,
 * /operations, /conversation, /assessments/new, /reports/:id, /monitoring)
 * are intentionally NOT mounted (dropped per the project decision); the
 * files remain on disk, excluded from the build (see DORMANT_FILES.md).
 */
import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { RequireAuth } from "./routeGuards";
import LoadingScreen from "../components/common/LoadingScreen";
import AppShell from "../components/layout/AppShell";

const Landing = lazy(() => import("../pages/LandingPage"));
const Register = lazy(() => import("../pages/RegisterPage"));
const Contact = lazy(() => import("../pages/ContactPage"));
const Verify = lazy(() => import("../pages/VerifyEmailPage"));
const Login = lazy(() => import("../pages/LoginPage"));
const Forgot = lazy(() => import("../pages/ForgotPasswordPage"));
const ApiTest = lazy(() => import("../pages/ApiTestPage"));

const Chat = lazy(() => import("../pages/ChatPage"));
const Assessments = lazy(() => import("../pages/AssessmentsPage"));
const Reports = lazy(() => import("../pages/ReportsPage"));
const Notifications = lazy(() => import("../pages/NotificationsPage"));
const Profile = lazy(() => import("../pages/ProfilePage"));
const Billing = lazy(() => import("../pages/BillingPage"));
const Settings = lazy(() => import("../pages/SettingsPage"));
const Admin = lazy(() => import("../pages/AdminPage"));
const AdminLogin = lazy(() => import("../pages/AdminLoginPage"));

const Privacy = lazy(() => import("../pages/PrivacyPolicyPage"));
const Terms = lazy(() => import("../pages/TermsOfServicePage"));
const Compliance = lazy(() => import("../pages/LegalCompliancePage"));

const NotFound = lazy(() => import("../components/errors/NotFoundPage"));
const Unauthorized = lazy(() => import("../components/errors/UnauthorizedPage"));
const ServerError = lazy(() => import("../components/errors/ServerErrorPage"));
const Maintenance = lazy(() => import("../components/errors/MaintenancePage"));

export default function AppRouter() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        {/* ── public ── */}
        <Route path="/" element={<Landing />} />
        <Route path="/register" element={<Register />} />
        <Route path="/verify-email" element={<Verify />} />
        <Route path="/login" element={<Login />} />
        <Route path="/contact" element={<Contact />} />
        <Route path="/forgot-password" element={<Forgot />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms" element={<Terms />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/dev/api" element={<ApiTest />} />
        {/* Hidden hardened admin portal — deliberately NOT linked anywhere.
            Admin accounts are rejected on the standard /login endpoint. */}
        <Route path="/admin/login" element={<AdminLogin />} />

        {/* system pages */}
        <Route path="/unauthorized" element={<Unauthorized />} />
        <Route path="/server-error" element={<ServerError />} />
        <Route path="/maintenance" element={<Maintenance />} />

        {/* legacy redirect */}
        <Route path="/dashboard" element={<Navigate to="/chat" replace />} />

        {/* ── app (authenticated) ── */}
        <Route element={<RequireAuth />}>
          <Route element={<AppShell />}>
            <Route path="/chat" element={<Chat />} />
            <Route path="/chat/:id" element={<Chat />} />
            <Route path="/assessments" element={<Assessments />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/billing" element={<Billing />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/admin/*" element={<Admin />} />
          </Route>
        </Route>

        {/* 404 */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}
