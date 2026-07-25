/** VerifyOTPForm — 6-digit OTP form + countdown + resend. */
import { useState } from "react";
import InputOTP from "../ui/InputOTP";
import Button from "../ui/Button";

interface VerifyOTPFormProps {
  onSubmit: (otp: string) => void;
  onResend: () => void;
  countdown: number;
  canResend: boolean;
  isLoading?: boolean;
  error?: string;
}

const formatCountdown = (seconds: number) =>
  `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;

export default function VerifyOTPForm({
  onSubmit,
  onResend,
  countdown,
  canResend,
  isLoading,
  error,
}: VerifyOTPFormProps) {
  const [otp, setOtp] = useState(["", "", "", "", "", ""] as string[]);

  const handleVerify = () => {
    const code = otp.join("");
    if (code.length === 6 && countdown > 0) {
      onSubmit(code);
    }
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}
      <InputOTP value={otp} onChange={setOtp} />
      <p className="text-center text-sm text-gray-400">
        Code expires in:{" "}
        <span
          className={`font-mono ${countdown < 60 ? "text-red-400" : "text-cerberus-blue"}`}
        >
          {formatCountdown(countdown)}
        </span>
      </p>
      <Button
        onClick={handleVerify}
        disabled={otp.some((d) => !d) || isLoading || countdown <= 0}
        loading={isLoading}
        className="w-full"
      >
        Verify Account
      </Button>
      <button
        onClick={onResend}
        disabled={!canResend}
        className="w-full text-sm text-cerberus-blue hover:underline disabled:opacity-50"
      >
        Resend Code
      </button>
    </div>
  );
}
