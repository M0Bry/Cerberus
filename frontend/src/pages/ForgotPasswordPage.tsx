/**
 * Forgot Password Page (new design) — ported from the new front-end's forgot.html.
 *
 * Two-step flow (identical to the mock):
 *   step 1: email → request reset code
 *   step 2: 6-digit code + new password → reset
 *
 * ⚠️ Backend endpoints `POST /auth/forgot-password` and `POST /auth/reset-password`
 * are NOT implemented yet (phase 2 — see CHANGE_LIST.md). When they are missing
 * (HTTP 404/405) the page shows an explicit "service not available yet" notice
 * instead of a confusing error, and the user is not moved to step 2.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import AuthLayout from "../components/layout/AuthLayout";
import OtpInput from "../components/ui/OtpInput";
import { useReveal } from "../hooks/useReveal";
import { authApi } from "../api/authApi";
import { AUTH_CONFIG } from "../config/auth";
import { checkEmail, checkOTP, checkPassword } from "../utils/validators";

function isMissingEndpoint(err: any): boolean {
  const status = err?.response?.status;
  return status === 404 || status === 405 || status === 501;
}

export default function ForgotPasswordPage() {
  const revealRef = useReveal<HTMLDivElement>();
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [serviceUnavailable, setServiceUnavailable] = useState(false);
  const [success, setSuccess] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState<number>(AUTH_CONFIG.resetCodeSeconds);

  const codeComplete = code.length === AUTH_CONFIG.otpLength;
  const pwValid = newPassword.length >= AUTH_CONFIG.passwordMinLength;

  /* reset-code countdown (runs while step 2 is visible) */
  useEffect(() => {
    if (step !== 2) return;
    const t = window.setInterval(() => setSecondsLeft((s) => Math.max(0, s - 1)), 1000);
    return () => window.clearInterval(t);
  }, [step]);

  const requestMutation = useMutation<any, any, { email: string }>({
    mutationFn: (data) => authApi.forgotPassword(data).then((r) => r.data),
    onSuccess: () => {
      setError("");
      setStep(2);
    },
    onError: (err) => {
      if (isMissingEndpoint(err)) {
        setServiceUnavailable(true);
        setError("");
      } else {
        setServiceUnavailable(false);
        setError(
          err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Could not send the reset code"
        );
      }
    },
  });

  const resetMutation = useMutation<any, any, { email: string; otp: string; new_password: string }>({
    mutationFn: (data) => authApi.resetPassword(data).then((r) => r.data),
    onSuccess: () => {
      setSuccess(true);
      setError("");
      window.setTimeout(() => {
        window.location.href = "/login";
      }, 1600);
    },
    onError: (err) => {
      if (isMissingEndpoint(err)) {
        setServiceUnavailable(true);
        setStep(1);
      } else {
        setError(
          err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Password reset failed"
        );
      }
    },
  });

  return (
    <AuthLayout>
      <div ref={revealRef} className="auth-panel fade-up">
        {serviceUnavailable && (
          <div className="alert show warn" style={{ marginBottom: 14 }}>
            Password reset is not available in this environment yet — the backend endpoint is pending (phase 2).
            Please contact support to restore access.
          </div>
        )}

        {step === 1 && (
          <div id="fpStep1">
            <h1 className="auth-title">Reset Password</h1>
            <p className="auth-sub">Enter your registered email and we'll send a secure reset code.</p>
            {error && <div className="alert show err">{error}</div>}
            <form
              noValidate
              onSubmit={(e) => {
                e.preventDefault();
                setError("");
                const emailErr = checkEmail(email);
                if (emailErr) return setError(emailErr);
                requestMutation.mutate({ email: email.trim() });
              }}
            >
              <div className="form-group">
                <label>Registered Email</label>
                <input type="email" required placeholder="john@acme.com" value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <button className="btn btn-primary" style={{ width: "100%" }} disabled={requestMutation.isPending || !email}>
                <i className="fas fa-paper-plane" /> {requestMutation.isPending ? "Sending reset code…" : "Send Reset Code"}
              </button>
            </form>
          </div>
        )}

        {step === 2 && (
          <div id="fpStep2">
            <h1 className="auth-title">Enter Reset Code</h1>
            <p className="auth-sub">A 6-digit reset code has been sent to your email address.</p>
            {error && <div className="alert show err">{error}</div>}
            {success && (
              <div className="alert show ok">Password updated successfully. You may now log in with your new password.</div>
            )}
            <OtpInput value={code} onChange={setCode} disabled={codeComplete || success} />
            <p className="countdown">
              Code expires in: <b>{String(Math.floor(secondsLeft / 60)).padStart(2, "0")}:{String(secondsLeft % 60).padStart(2, "0")}</b>
            </p>
            <div className="form-group">
              <label>New Password</label>
              <div className="pw-wrap">
                <input
                  type={showPw ? "text" : "password"}
                  minLength={AUTH_CONFIG.passwordMinLength}
                  placeholder="••••••••"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
                <button type="button" className={`pw-toggle fas fa-${showPw ? "eye-slash" : "eye"}`} aria-label="Toggle password" onClick={() => setShowPw((v) => !v)} />
              </div>
              <div className="form-note">Min {AUTH_CONFIG.passwordMinLength} characters — mixed case, number and symbol recommended.</div>
            </div>
            <button
              className="btn btn-primary"
              style={{ width: "100%" }}
              disabled={!codeComplete || !pwValid || resetMutation.isPending || success}
              onClick={() => {
                const otpErr = checkOTP(code);
                if (otpErr) return setError(otpErr);
                const pwErr = checkPassword(newPassword);
                if (pwErr) return setError(pwErr);
                resetMutation.mutate({ email: email.trim(), otp: code, new_password: newPassword });
              }}
            >
              <i className="fas fa-rotate" /> {resetMutation.isPending ? "Resetting…" : "Reset Password"}
            </button>
          </div>
        )}

        <p className="auth-foot">
          Remembered it? <Link to="/login">Back to Log In</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
