/**
 * useVerifyEmail — OTP verification + resend + countdown.
 */
import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { authApi } from "../api/authApi";

export function useVerifyEmail(email: string) {
  const [countdown, setCountdown] = useState(300);
  const [canResend, setCanResend] = useState(false);

  useEffect(() => {
    if (countdown <= 0) {
      setCanResend(true);
      return;
    }
    const t = setInterval(() => setCountdown((c) => c - 1), 1000);
    return () => clearInterval(t);
  }, [countdown]);

  const verifyMutation = useMutation({
    mutationFn: (otp: string) => authApi.verifyOtp({ email, otp }),
  });

  const resendMutation = useMutation({
    mutationFn: () => authApi.resendOtp({ email }),
    onSuccess: () => {
      setCountdown(300);
      setCanResend(false);
    },
  });

  return { verifyMutation, resendMutation, countdown, canResend };
}
