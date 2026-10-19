/**
 * OtpInput — 6 single-digit boxes with auto-advance, backspace and paste.
 * Ported from the new front-end's js/app.js (initOTP).
 *
 * Controlled via `onChange` (full code string) — the parent decides validity.
 */
import { useCallback, useRef } from "react";

interface OtpInputProps {
  length?: number;
  value: string;
  onChange: (code: string) => void;
  disabled?: boolean;
  id?: string;
}

export default function OtpInput({ length = 6, value, onChange, disabled, id }: OtpInputProps) {
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  const setDigit = useCallback(
    (index: number, digit: string) => {
      const chars = value.padEnd(length, " ").split("");
      chars[index] = digit;
      let next = chars.join("").replace(/\s+$/g, "");
      // keep contiguous digits only
      next = next.slice(0, length);
      onChange(next);
    },
    [length, onChange, value]
  );

  const handleInput = (index: number, raw: string) => {
    const digit = raw.replace(/\D/g, "").slice(-1);
    setDigit(index, digit);
    if (digit && index < length - 1) refs.current[index + 1]?.focus();
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !value[index] && index > 0) {
      refs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    const digits = (e.clipboardData.getData("text").match(/\d/g) || []).slice(0, length);
    if (!digits.length) return;
    e.preventDefault();
    onChange(digits.join(""));
    const focusIdx = Math.min(digits.length, length - 1);
    refs.current[focusIdx]?.focus();
  };

  return (
    <div id={id} className="otp-row" onPaste={handlePaste}>
      {Array.from({ length }).map((_, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          inputMode="numeric"
          maxLength={1}
          aria-label={`Digit ${i + 1}`}
          disabled={disabled}
          value={value[i] || ""}
          className={value[i] ? "filled" : ""}
          onChange={(e) => handleInput(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
        />
      ))}
    </div>
  );
}
