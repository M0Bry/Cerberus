/**
 * AdminLoginPage — the HIDDEN, hardened admin sign-in.
 *
 *  * Not linked from anywhere — only reachable by typing the URL.
 *  * Separate from the standard /login: admin accounts are rejected there.
 *  * Two steps: credentials → one-time code emailed (90s TTL, 5 attempts).
 *  * Every attempt (success or failure) is audit-logged server-side and
 *    the portal is rate-limited per IP (5 / 15 min).
 *
 * On success it stores the standard token (same keys as /login) and
 * navigates to /admin.
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { adminApi } from "../api/adminApi";
import { userApi } from "../api/userApi";
import { useAuthStore } from "../store/useAuthStore";
import OtpInput from "../components/ui/OtpInput";
import type { User } from "../types";
import { checkEmail, checkOTP } from "../utils/validators";

const OTP_SECONDS = 90; // mirrors backend OTP_EXPIRE_SECONDS (01:30)

export default function AdminLoginPage() {
  const navigate = useNavigate();
  const { setTokens, setUser } = useAuthStore();

  const [step, setStep] = useState<"credentials" | "code">("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [secondsLeft, setSecondsLeft] = useState(OTP_SECONDS);
  const [resendIn, setResendIn] = useState(0);
  const timerRef = useRef<number | null>(null);
  const resendRef = useRef<number | null>(null);

  const startCountdown = () => {
    setSecondsLeft(OTP_SECONDS);
    if (timerRef.current) window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          if (timerRef.current) window.clearInterval(timerRef.current);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
  };

  const startResendCooldown = (secs: number) => {
    setResendIn(secs);
    if (resendRef.current) window.clearInterval(resendRef.current);
    resendRef.current = window.setInterval(() => {
      setResendIn((s) => {
        if (s <= 1) {
          if (resendRef.current) window.clearInterval(resendRef.current);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
  };

  useEffect(
    () => () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
      if (resendRef.current) window.clearInterval(resendRef.current);
    },
    []
  );

  const finishLogin = (access: string, refresh: string) => {
    setTokens(access, refresh);
    userApi
      .getProfile()
      .then((r) => {
        const d = r.data as User & { profile_image_url?: string | null };
        setUser({ ...d, avatar_url: d.profile_image_url || d.avatar_url || "" });
      })
      .catch(() => {
        /* profile lazy-loads in the app shell */
      })
      .finally(() => navigate("/admin", { replace: true }));
  };

  const loginMutation = useMutation({
    mutationFn: (d: { email: string; password: string }) =>
      adminApi.portalLogin(d).then((r) => r.data),
    onSuccess: (data) => {
      setError("");
      setNotice(data.message);
      setStep("code");
      startCountdown();
      startResendCooldown(30);
    },
    onError: (err: any) => {
      const message: string =
        err?.response?.data?.error?.message ||
        err?.response?.data?.detail ||
        "Sign-in failed. Please check your credentials.";
      if (err?.response?.status === 429) {
        setError("Too many attempts. This portal is rate-limited — try again in 15 minutes.");
      } else {
        setError(message);
      }
    },
  });

  const verifyMutation = useMutation({
    mutationFn: (d: { email: string; otp: string }) =>
      adminApi.portalVerify(d).then((r) => r.data),
    onSuccess: (data) => finishLogin(data.access_token, data.refresh_token),
    onError: (err: any) => {
      const message: string =
        err?.response?.data?.error?.message ||
        err?.response?.data?.detail ||
        "Verification failed.";
      if (err?.response?.status === 429) {
        setError("Too many attempts. This portal is rate-limited — try again in 15 minutes.");
        setCode("");
      } else {
        setError(message);
        if (secondsLeft <= 10) setCode("");
      }
    },
  });

  const submitCredentials = (e?: React.FormEvent) => {
    e?.preventDefault();
    setError("");
    const emailErr = checkEmail(email);
    if (emailErr) return setError(emailErr);
    if (!password) return setError("Enter your password.");
    loginMutation.mutate({ email: email.trim(), password });
  };

  const submitCode = (e?: React.FormEvent) => {
    e?.preventDefault();
    const otpErr = checkOTP(code);
    if (otpErr) return setError(otpErr);
    setError("");
    verifyMutation.mutate({ email: email.trim(), otp: code });
  };

  const resend = () => {
    if (resendIn > 0 || !email.trim()) return;
    setError("");
    setNotice("");
    loginMutation.mutate({ email: email.trim(), password });
    setCode("");
    startCountdown();
    startResendCooldown(30);
  };

  const mm = String(Math.floor(secondsLeft / 60)).padStart(1, "0");
  const ss = String(secondsLeft % 60).padStart(2, "0");

  const field: React.CSSProperties = {
    width: "100%",
    background: "rgba(0,0,0,.35)",
    border: "1px solid var(--border-strong)",
    borderRadius: 10,
    padding: "13px 16px",
    color: "var(--text-primary)",
    fontSize: 15,
    outline: "none",
    marginBottom: 12,
  };
  const label: React.CSSProperties = {
    display: "block",
    fontSize: 12,
    letterSpacing: 1,
    textTransform: "uppercase",
    color: "var(--text-muted)",
    marginBottom: 6,
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        background: "radial-gradient(1200px 600px at 50% -10%, rgba(0,212,255,.06), transparent), #0a0a1a",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 420,
          border: "1px solid var(--border-strong)",
          borderRadius: 16,
          background: "rgba(15,16,26,.92)",
          padding: "36px 34px 30px",
          boxShadow: "0 30px 80px rgba(0,0,0,.55)",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 26 }}>
          <div
            style={{
              width: 54,
              height: 54,
              margin: "0 auto 14px",
              borderRadius: 14,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "rgba(0,212,255,.08)",
              border: "1px solid rgba(0,212,255,.35)",
              color: "#00d4ff",
              fontSize: 22,
            }}
          >
            <i className="fas fa-shield-halved" />
          </div>
          <div
            style={{
              fontSize: 11,
              letterSpacing: 3,
              textTransform: "uppercase",
              color: "var(--text-muted)",
              marginBottom: 8,
            }}
          >
            Restricted Access
          </div>
          <h1
            style={{
              fontFamily: "var(--font-display)",
              fontSize: 22,
              letterSpacing: 1,
              margin: 0,
              color: "var(--text-primary)",
            }}
          >
            Cerberus Control Panel
          </h1>
        </div>

        {notice && step === "code" && (
          <div
            style={{
              background: "rgba(0,212,255,.07)",
              border: "1px solid rgba(0,212,255,.3)",
              borderRadius: 10,
              padding: "10px 14px",
              fontSize: 13,
              color: "var(--text-secondary)",
              marginBottom: 16,
            }}
          >
            <i className="fas fa-envelope-circle-check" /> {notice}
          </div>
        )}

        {error && (
          <div
            style={{
              background: "rgba(248,113,113,.08)",
              border: "1px solid rgba(248,113,113,.4)",
              borderRadius: 10,
              padding: "10px 14px",
              fontSize: 13,
              color: "#fca5a5",
              marginBottom: 16,
            }}
          >
            <i className="fas fa-triangle-exclamation" /> {error}
          </div>
        )}

        {step === "credentials" ? (
          <form onSubmit={submitCredentials} noValidate autoComplete="off">
            <label style={label} htmlFor="adm-email">
              Email
            </label>
            <input
              id="adm-email"
              type="email"
              style={field}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="off"
              placeholder="admin@cerberus-ai.com"
              required
            />
            <label style={label} htmlFor="adm-password">
              Password
            </label>
            <input
              id="adm-password"
              type="password"
              style={field}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              placeholder="••••••••••••"
              required
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loginMutation.isPending}
              style={{ width: "100%", padding: "13px 16px", marginTop: 6 }}
            >
              {loginMutation.isPending ? (
                <>
                  <i className="fas fa-spinner fa-spin" /> Checking…
                </>
              ) : (
                <>
                  <i className="fas fa-key" /> Continue
                </>
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={submitCode} noValidate autoComplete="off">
            <div style={{ textAlign: "center", marginBottom: 18 }}>
              <div style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: 8 }}>
                Enter the 6-digit code sent to <b>{email}</b>
              </div>
              <div
                style={{
                  fontSize: 13,
                  color: secondsLeft > 0 ? "var(--text-muted)" : "#f87171",
                  fontVariantNumeric: "tabular-nums",
                }}
              >
                <i className="fas fa-hourglass-half" />{" "}
                {secondsLeft > 0 ? `Code expires in ${mm}:${ss}` : "Code expired — request a new one"}
              </div>
            </div>
            <OtpInput value={code} onChange={setCode} disabled={secondsLeft <= 0 || verifyMutation.isPending} />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={code.length < 6 || secondsLeft <= 0 || verifyMutation.isPending}
              style={{ width: "100%", padding: "13px 16px", marginTop: 18 }}
            >
              {verifyMutation.isPending ? (
                <>
                  <i className="fas fa-spinner fa-spin" /> Verifying…
                </>
              ) : (
                <>
                  <i className="fas fa-right-to-bracket" /> Verify &amp; Enter
                </>
              )}
            </button>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 14 }}>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ padding: "8px 10px", fontSize: 13 }}
                onClick={() => {
                  setStep("credentials");
                  setCode("");
                  setError("");
                  setNotice("");
                  if (timerRef.current) window.clearInterval(timerRef.current);
                }}
              >
                <i className="fas fa-arrow-left" /> Change account
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ padding: "8px 10px", fontSize: 13 }}
                disabled={resendIn > 0}
                onClick={resend}
              >
                {resendIn > 0 ? `Resend in ${resendIn}s` : "Resend code"}
              </button>
            </div>
          </form>
        )}

        <p
          style={{
            marginTop: 26,
            fontSize: 11,
            lineHeight: 1.6,
            color: "var(--text-muted)",
            textAlign: "center",
          }}
        >
          <i className="fas fa-user-shield" /> Authorized administrators only. All attempts on
          this portal are recorded and monitored.
        </p>
      </div>
    </div>
  );
}
