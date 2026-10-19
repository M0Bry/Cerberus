/**
 * Verify Email Page (new design) — ported from the new front-end's verify.html.
 *
 * Real wiring:
 *  - POST /auth/verify-otp {email, otp}  (authApi)
 *  - POST /auth/resend-otp {email}       (authApi, 30s cooldown)
 *  - 6-box OTP with paste, countdown (code validity = 5 min per spec),
 *    masked email, expired state.
 *
 * The email comes from router state (set by the register page) or the
 * "cerberus_remember" / "cerberus_last_email" keys as fallbacks.
 */
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import AuthLayout from "../components/layout/AuthLayout";
import OtpInput from "../components/ui/OtpInput";
import { useReveal } from "../hooks/useReveal";
import { authApi } from "../api/authApi";
import { AUTH_CONFIG } from "../config/auth";
import { checkOTP } from "../utils/validators";
import { maskEmail } from "../utils/formatters";

const formatCountdown = (seconds: number) =>
  `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;

export default function VerifyEmailPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const revealRef = useReveal<HTMLDivElement>();

  const routeState = (location.state || {}) as { email?: string; resend?: boolean };
  const [email] = useState<string>(() => {
    try {
      return (
        routeState.email ||
        localStorage.getItem("cerberus_remember") ||
        localStorage.getItem("cerberus_last_email") ||
        ""
      );
    } catch {
      return routeState.email || "";
    }
  });
  const [info, setInfo] = useState("");

  const [code, setCode] = useState("");
  const [secondsLeft, setSecondsLeft] = useState<number>(AUTH_CONFIG.otpExpirySeconds);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");
  const [resendIn, setResendIn] = useState(0);
  const timerRef = useRef<number | null>(null);
  const resendTimerRef = useRef<number | null>(null);

  const complete = code.length === AUTH_CONFIG.otpLength;
  const expired = secondsLeft <= 0;

  /* countdown */
  useEffect(() => {
    timerRef.current = window.setInterval(() => {
      setSecondsLeft((s) => Math.max(0, s - 1));
    }, 1000);
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
    };
  }, []);

  /* resend cooldown */
  useEffect(() => {
    if (resendIn <= 0) return;
    resendTimerRef.current = window.setTimeout(() => setResendIn((v) => v - 1), 1000);
    return () => {
      if (resendTimerRef.current) window.clearTimeout(resendTimerRef.current);
    };
  }, [resendIn]);

  useEffect(() => () => {
    if (timerRef.current) window.clearInterval(timerRef.current);
    if (resendTimerRef.current) window.clearTimeout(resendTimerRef.current);
  }, []);

  const verifyMutation = useMutation<any, any, { email: string; otp: string }>({
    mutationFn: (data) => authApi.verifyOtp(data).then((r) => r.data),
    onSuccess: () => {
      setSuccess(true);
      setError("");
      try {
        localStorage.setItem("cerberus_last_email", email);
      } catch {
        /* ignore */
      }
      window.setTimeout(() => navigate("/login"), 1600);
    },
    onError: (err) => {
      const message: string =
        err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Verification failed";
      setError(message);
    },
  });

  /*
   * Verification gate: when the login attempt is rejected because the
   * account is unverified, the login page lands here with resend:true and
   * the code is sent automatically — the user only types the 6 digits.
   */
  const autoResendRef = useRef(false);
  useEffect(() => {
    if (autoResendRef.current || !email || !routeState.resend) return;
    autoResendRef.current = true;
    authApi
      .resendOtp({ email })
      .then(() => {
        setCode("");
        setError("");
        setInfo("A new verification code has just been sent to your inbox.");
        setSecondsLeft(AUTH_CONFIG.otpExpirySeconds);
        setResendIn(AUTH_CONFIG.otpResendCooldownSeconds);
      })
      .catch((err) => {
        const msg: string =
          err?.response?.data?.error?.message || err?.message || "";
        if (/cooldown|wait|seconds|too soon|recently|only every/i.test(msg)) {
          // A code was sent very recently and may still be valid (90s).
          setInfo("Check your inbox — your verification code may already be waiting.");
        } else {
          setError("Could not send a new code automatically. Use the resend button below.");
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email, routeState.resend]);

  const resendMutation = useMutation<any, any, { email: string }>({
    mutationFn: (data) => authApi.resendOtp(data).then((r) => r.data),
    onSuccess: () => {
      setCode("");
      setError("");
      setSecondsLeft(AUTH_CONFIG.otpExpirySeconds);
      setResendIn(AUTH_CONFIG.otpResendCooldownSeconds);
    },
    onError: (err) => {
      const message: string =
        err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Could not resend the code";
      setError(message);
    },
  });

  if (!email) {
    return (
      <AuthLayout backTo="/" backLabel="Home">
        <div ref={revealRef} className="sys-panel fade-up">
          <div className="sys-icon">
            <i className="fas fa-envelope-open-text" />
          </div>
          <p className="sys-tag">
            Account <b>Activation</b>
          </p>
          <h1 className="auth-title sys-title">Verify Email</h1>
          <p className="sys-sub">We could not determine which email to verify.</p>
          <p className="auth-foot">
            <Link to="/login">Back to Log In</Link>
          </p>
        </div>
      </AuthLayout>
    );
  }


  return (
    <AuthLayout backTo="/" backLabel="Home">
      <div ref={revealRef} className="sys-panel fade-up">
        <div className="sys-icon">
          <i className="fas fa-envelope-open-text" />
        </div>
        <p className="sys-tag">
          Account <b>Activation</b>
        </p>
        <h1 className="auth-title sys-title">Verify Email</h1>
        <p className="sys-sub">Enter the 6-digit code we sent to your inbox.</p>
        <p className="masked-mail">
          Code sent to <b>{maskEmail(email)}</b>
        </p>

        {error && !success && <div className="alert show err" style={{ marginTop: 12 }}>{error}</div>}
        {info && !success && <div className="alert show ok" style={{ marginTop: 12 }}>{info}</div>}
        {success && (
          <div className="alert show ok" style={{ marginTop: 12 }}>
            Your email has been verified successfully. Your account is now active — redirecting to sign in…
          </div>
        )}

        {/* Boxes must be ENABLED while typing. Lock only once the code is
            complete / verified / expired (matches ForgotPasswordPage). */}
        <OtpInput value={code} onChange={setCode} disabled={complete || success || expired} />
        <p className={`countdown${expired ? " expired" : ""}`}>
          {expired ? (
            "Code expired"
          ) : (
            <>
              Expires in <b>{formatCountdown(secondsLeft)}</b>
            </>
          )}
        </p>

        <button
          className="btn btn-primary verify-btn"
          disabled={!complete || success || verifyMutation.isPending || (expired && !resendMutation.isSuccess)}
          onClick={() => {
            const otpErr = checkOTP(code);
            if (otpErr) return setError(otpErr);
            verifyMutation.mutate({ email, otp: code });
          }}
        >
          {success ? (
            <>
              <i className="fas fa-check" /> Verified
            </>
          ) : verifyMutation.isPending ? (
            <>
              <i className="fas fa-key" /> Validating code…
            </>
          ) : (
            <>
              <i className="fas fa-key" /> Verify Account
            </>
          )}
        </button>

        <p className="auth-foot">
          No code?{" "}
          <button
            type="button"
            className="lnk"
            style={{ background: "none", border: "none", cursor: resendIn ? "default" : "pointer", color: "var(--accent)" }}
            disabled={resendIn > 0 || resendMutation.isPending}
            onClick={() => resendMutation.mutate({ email })}
          >
            {resendIn > 0 ? `Resend code (${resendIn}s)` : resendMutation.isPending ? "Sending…" : "Resend Code"}
          </button>
        </p>
      </div>
    </AuthLayout>
  );
}
