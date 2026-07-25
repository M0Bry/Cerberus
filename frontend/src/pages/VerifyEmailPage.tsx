/**
 * Verify Email Page — Uses useVerifyEmail hook for OTP logic.
 */

import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import AuthLayout from "../components/layout/AuthLayout";
import InputOTP from "../components/ui/InputOTP";
import Button from "../components/ui/Button";
import { useVerifyEmail } from "../hooks/useVerifyEmail";

export default function VerifyEmailPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const email = (location.state as any)?.email || "";
  const emailMasked = (location.state as any)?.emailMasked || "***@***.com";

  const [otp, setOtp] = useState<string[]>(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const { verifyMutation, resendMutation, countdown, canResend } = useVerifyEmail(email);

  const formatTime = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const handleVerify = () => {
    setError("");
    verifyMutation.mutate(otp.join(""), {
      onSuccess: () => {
        setSuccess(true);
        setTimeout(() => navigate("/login"), 3000);
      },
      onError: (err: any) =>
        setError(err.response?.data?.error?.message || "Verification failed"),
    });
  };

  const handleResend = () => {
    resendMutation.mutate(undefined, {
      onError: (err: any) =>
        setError(err.response?.data?.error?.message || "Failed to resend"),
    });
  };

  const isComplete = otp.every((d) => d !== "");
  const expired = countdown <= 0;

  if (success) {
    return (
      <AuthLayout>
        <div className="text-center space-y-4">
          <h2 className="text-3xl font-bold text-white">Email Verified!</h2>
          <div className="cyber-card">
            <div className="text-5xl mb-4">✅</div>
            <p className="text-gray-300">
              Your email has been verified successfully. Your account is now active,
              and you may proceed to sign in.
            </p>
            <p className="text-sm text-gray-400 mt-4">Redirecting to login page...</p>
          </div>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <div className="text-center space-y-4">
        <h2 className="text-3xl font-bold text-white">Verify Your Email</h2>
        <p className="text-gray-400">
          A security verification code has been sent to your registered email address.
        </p>
        <div className="cyber-card mt-4">
          {error && (
            <div className="p-3 mb-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <p className="text-sm text-gray-400 mb-1">Verification code sent to:</p>
          <p className="text-cerberus-blue font-mono text-sm mb-6">{emailMasked}</p>

          <InputOTP length={6} value={otp} onChange={setOtp} disabled={expired} error={error} />

          <div className="text-center mt-4 mb-6">
            {!expired ? (
              <p className="text-sm text-gray-400">
                Code expires in:{" "}
                <span className="font-mono text-cerberus-blue">{formatTime(countdown)}</span>
              </p>
            ) : (
              <p className="text-sm text-cerberus-red">
                Your verification code has expired. Request a new one to continue.
              </p>
            )}
          </div>

          {!expired ? (
            <Button
              onClick={handleVerify}
              disabled={!isComplete || verifyMutation.isPending}
              loading={verifyMutation.isPending}
              className="w-full"
            >
              Verify Account
            </Button>
          ) : (
            <Button
              onClick={handleResend}
              disabled={!canResend || resendMutation.isPending}
              loading={resendMutation.isPending}
              className="w-full"
            >
              {canResend ? "Resend Code" : `Resend in ${formatTime(countdown)}`}
            </Button>
          )}
        </div>
      </div>
    </AuthLayout>
  );
}
