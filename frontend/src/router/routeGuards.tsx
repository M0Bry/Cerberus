/**
 * Route Guards — RequireAuth, RequireVerified, RequireAdmin with proper role checks.
 */
import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../store/useAuthStore";

/**
 * Requires user to be authenticated.
 */
export function RequireAuth() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <Outlet />;
}

/**
 * Requires user to be authenticated AND have verified email.
 */
export function RequireVerified() {
  const { isAuthenticated, user } = useAuthStore();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (user && user.status !== "verified") return <Navigate to="/verify-email" replace />;
  return <Outlet />;
}

/**
 * Requires user to be authenticated AND have admin role.
 */
export function RequireAdmin() {
  const { isAuthenticated, user } = useAuthStore();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (!user || (user.role !== "admin" && user.role !== "super_admin")) {
    return <Navigate to="/dashboard" replace />;
  }
  return <Outlet />;
}

/**
 * Requires user to be a pentester or admin.
 */
export function RequirePentester() {
  const { isAuthenticated, user } = useAuthStore();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (
    !user ||
    !["pentester", "admin", "super_admin"].includes(user.role)
  ) {
    return <Navigate to="/dashboard" replace />;
  }
  return <Outlet />;
}
