/**
 * InputOTP — 6-digit OTP input matching the exact reference design.
 */
import { useRef, KeyboardEvent, ClipboardEvent } from "react";

interface InputOTPProps {
  length?: number;
  value: string[];
  onChange: (otp: string[]) => void;
  disabled?: boolean;
  error?: string;
}

export default function InputOTP({ length = 6, value, onChange, disabled, error }: InputOTPProps) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);

  const handleChange = (index: number, char: string) => {
    if (!/^[0-9]?$/.test(char)) return;
    const next = [...value];
    next[index] = char.slice(-1);
    onChange(next);
    if (char && index < length - 1) refs.current[index + 1]?.focus();
  };

  const handleKeyDown = (index: number, e: KeyboardEvent) => {
    if (e.key === "Backspace" && !value[index] && index > 0) {
      refs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: ClipboardEvent) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, length);
    const next = [...value];
    for (let i = 0; i < pasted.length; i++) next[i] = pasted[i];
    onChange(next);
    refs.current[Math.min(pasted.length, length - 1)]?.focus();
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "center", gap: 10, marginBottom: 20 }} onPaste={handlePaste}>
        {Array.from({ length }).map((_, i) => (
          <input
            key={i}
            ref={(el) => (refs.current[i] = el)}
            className="otp-input"
            value={value[i] || ""}
            maxLength={1}
            inputMode="numeric"
            disabled={disabled}
            onChange={(e) => handleChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
          />
        ))}
      </div>
      {error && (
        <p style={{ textAlign: "center", fontSize: 12, color: "#f4536b", fontFamily: "'Share Tech Mono', monospace" }}>
          {error}
        </p>
      )}
    </div>
  );
}
