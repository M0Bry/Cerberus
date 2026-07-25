import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";
import { RequireAuth, RequireAdmin } from "./routeGuards";
import LoadingScreen from "../components/common/LoadingScreen";

const Landing = lazy(() => import("../pages/LandingPage"));
const Register = lazy(() => import("../pages/RegisterPage"));
const Verify = lazy(() => import("../pages/VerifyEmailPage"));
const Login = lazy(() => import("../pages/LoginPage"));
const Forgot = lazy(() => import("../pages/ForgotPasswordPage"));
const Reset = lazy(() => import("../pages/ResetPasswordPage"));
const Dashboard = lazy(() => import("../pages/DashboardPage"));
const Chat = lazy(() => import("../pages/ChatPage"));
const Conversation = lazy(() => import("../pages/ConversationPage"));
const NewAssessment = lazy(() => import("../pages/NewAssessmentPage"));
const Assessments = lazy(() => import("../pages/AssessmentsPage"));
const Scope = lazy(() => import("../pages/ScopePage"));
const OSINT = lazy(() => import("../pages/OSINTPage"));
const RedTeam = lazy(() => import("../pages/RedTeamPage"));
const Risk = lazy(() => import("../pages/RiskAssessmentPage"));
const Reports = lazy(() => import("../pages/ReportsPage"));
const ReportView = lazy(() => import("../pages/ReportViewPage"));
const Profile = lazy(() => import("../pages/ProfilePage"));
const Operations = lazy(() => import("../pages/OperationsPage"));
const Settings = lazy(() => import("../pages/SettingsPage"));
const Notifications = lazy(() => import("../pages/NotificationsPage"));
const Admin = lazy(() => import("../pages/AdminPage"));
const Monitor = lazy(() => import("../pages/MonitoringPage"));
const Privacy = lazy(() => import("../pages/PrivacyPolicyPage"));
const Terms = lazy(() => import("../pages/TermsOfServicePage"));
const Compliance = lazy(() => import("../pages/LegalCompliancePage"));
const Contact = lazy(() => import("../pages/ContactPage"));
const NotFound = lazy(() => import("../pages/NotFoundPage"));

export default function AppRouter() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        {/* Public Routes */}
        <Route path="/" element={<Landing />} />
        <Route path="/register" element={<Register />} />
        <Route path="/verify-email" element={<Verify />} />
        <Route path="/login" element={<Login />} />
        <Route path="/forgot-password" element={<Forgot />} />
        <Route path="/reset-password" element={<Reset />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/terms" element={<Terms />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/contact" element={<Contact />} />

        {/* Protected Routes */}
        <Route element={<RequireAuth />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/assessments" element={<Assessments />} />
          <Route path="/assessments/new" element={<NewAssessment />} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/chat/:id" element={<Chat />} />
          <Route path="/conversation/:id" element={<Conversation />} />
          <Route path="/scope/:id" element={<Scope />} />
          <Route path="/osint/:id" element={<OSINT />} />
          <Route path="/redteam/:id" element={<RedTeam />} />
          <Route path="/risk/:id" element={<Risk />} />
          <Route path="/operations/:id" element={<Operations />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/reports/:id" element={<ReportView />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/notifications" element={<Notifications />} />
        </Route>

        {/* Admin Routes */}
        <Route element={<RequireAdmin />}>
          <Route path="/admin/*" element={<Admin />} />
          <Route path="/monitoring" element={<Monitor />} />
        </Route>

        {/* 404 */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
  );
}
