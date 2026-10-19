/**
 * Login Page (new design) — ported from the new front-end's login.html.
 *
 * Real wiring:
 *  - POST /auth/login (authApi)
 *  - unverified accounts are rejected by the backend → dedicated banner
 *    with a shortcut to /verify-email
 *  - "Remember me" persists the email in localStorage ("cerberus_remember")
 *  - after login: tokens → auth store, profile via GET /users/me, redirect to /chat
 */
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import AuthLayout from "../components/layout/AuthLayout";
import StateLink from "../components/common/StateLink";
import { useReveal } from "../hooks/useReveal";
import { authApi } from "../api/authApi";
import { userApi } from "../api/userApi";
import { useAuthStore } from "../store/useAuthStore";
import { AUTH_CONFIG } from "../config/auth";
import { checkEmail } from "../utils/validators";
import type { User } from "../types";

interface LoginResponse {
  success: boolean;
  access_token: string;
  refresh_token: string;
  token_type?: string;
  expires_in?: number;
}

export default function LoginPage() {
  const navigate = useNavigate();
  const revealRef = useReveal<HTMLDivElement>();
  const { setTokens, setUser } = useAuthStore();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState("");
  const [unverified, setUnverified] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem(AUTH_CONFIG.rememberKey);
    if (saved) {
      setEmail(saved);
      setRemember(true);
    }
  }, []);

  const loginMutation = useMutation<LoginResponse, any, { email: string; password: string }>({
    mutationFn: (data) => authApi.login(data).then((r) => r.data),
    onSuccess: (data) => {
      setTokens(data.access_token, data.refresh_token);
      // Best-effort: load the profile so the sidebar/topbar can render real data.
      userApi
        .getProfile()
        .then((r) => {
          const d = r.data as User & { profile_image_url?: string | null };
          setUser({ ...d, avatar_url: d.profile_image_url || d.avatar_url || "" });
        })
        .catch(() => {
          /* profile will be lazy-loaded by the app pages */
        });
      navigate(AUTH_CONFIG.dashboardPath);
    },
    onError: (err) => {
      const message: string =
        err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Login failed";
      if (/not yet been activated|verify your email/i.test(message)) {
        // Verification gate: no login without verification.
        // Automatically take the user to the verify page and fire a fresh
        // OTP — they only have to type the code.
        setUnverified(true);
        navigate("/verify-email", { state: { email: email.trim(), resend: true } });
      } else {
        setUnverified(false);
        setError(message);
      }
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setUnverified(false);
    // Client-side validation (the backend re-checks everything).
    const emailErr = checkEmail(email);
    if (emailErr) return setError(emailErr);
    if (!password) return setError("Enter your password.");
    if (remember) localStorage.setItem(AUTH_CONFIG.rememberKey, email.trim());
    else localStorage.removeItem(AUTH_CONFIG.rememberKey);
    loginMutation.mutate({ email: email.trim(), password });
  };

  return (
    <AuthLayout>
      <div ref={revealRef} className="auth-panel fade-up">
        <h1 className="auth-title">Welcome back</h1>
        <p className="auth-sub">Sign in to your security workspace</p>

        {error && <div className="alert show err">{error}</div>}

        {unverified && (
          <div className="alert show warn">
            Your account has not yet been activated. Please{" "}
            <StateLink to="/verify-email" state={{ email }} className="nl">
              verify your email address
            </StateLink>{" "}
            before signing in.
          </div>
        )}

        <form onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label>Corporate Email</label>
            <input name="email" type="email" required placeholder="john@acme.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="form-group">
            <label>Password</label>
            <div className="pw-wrap">
              <input
                id="loginPw"
                name="password"
                type={showPw ? "text" : "password"}
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button type="button" className={`pw-toggle fas fa-${showPw ? "eye-slash" : "eye"}`} aria-label="Toggle password" onClick={() => setShowPw((v) => !v)} />
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", margin: "4px 0 18px", fontSize: ".85rem" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-secondary)", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                style={{ accentColor: "var(--accent)", width: 14, height: 14 }}
              />{" "}
              Remember me
            </label>
            <Link to="/forgot-password" style={{ color: "var(--accent)", textDecoration: "none" }}>
              Forgot password?
            </Link>
          </div>
          <button className="btn btn-primary" style={{ width: "100%" }} disabled={loginMutation.isPending}>
            <i className="fas fa-fingerprint" /> {loginMutation.isPending ? "Authenticating…" : "Log In"}
          </button>
        </form>
        <p className="auth-foot">
          New To Cerberus? <Link to="/register">Create Account</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
