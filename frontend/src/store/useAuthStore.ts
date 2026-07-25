import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "../types";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  setTokens: (access: string, refresh: string) => void;
  setUser: (user: User) => void;
  logout: () => void;
}

/**
 * Token storage strategy:
 * - In development: localStorage for simplicity
 * - In production: httpOnly cookies set by the backend (no localStorage)
 *
 * The backend should set tokens as httpOnly, Secure, SameSite=Strict cookies.
 * The frontend only needs to know if the user is authenticated.
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      setTokens: (access, refresh) => {
        // In production: tokens are set as httpOnly cookies by the backend.
        // localStorage is only used as a development fallback.
        if (import.meta.env.DEV) {
          localStorage.setItem("access_token", access);
          localStorage.setItem("refresh_token", refresh);
        }
        set({ isAuthenticated: true });
      },
      setUser: (user) => set({ user }),
      logout: () => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        set({ user: null, isAuthenticated: false });
      },
    }),
    {
      name: "cerberus-auth",
      partialize: (s) => ({ isAuthenticated: s.isAuthenticated }),
    }
  )
);
