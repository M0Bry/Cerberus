/**
 * useAuth Hook — Custom hook for authentication state and actions.
 */

import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/useAuthStore";
import { authService } from "../services/auth";

export function useLogin() {
  const navigate = useNavigate();
  const { setTokens } = useAuthStore();

  return useMutation({
    mutationFn: authService.login,
    onSuccess: (data) => {
      setTokens(data.data.access_token, data.data.refresh_token);
      navigate("/dashboard");
    },
  });
}

export function useLogout() {
  const navigate = useNavigate();
  const { logout } = useAuthStore();

  return () => {
    authService.logout().catch(() => {});
    logout();
    navigate("/login");
  };
}

export function useIsAuthenticated() {
  return useAuthStore((s) => s.isAuthenticated);
}
