/**
 * Input — Field input matching the exact reference design.
 */
import { InputHTMLAttributes, forwardRef, ReactNode } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  icon?: ReactNode;
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, icon, style, ...props }, ref) => {
    return (
      <div style={{ marginBottom: 16 }}>
        {label && (
          <label
            style={{
              display: "block",
              fontSize: 12.5,
              color: "#8493ac",
              marginBottom: 7,
              fontFamily: MONO,
            }}
          >
            {label}
          </label>
        )}
        <div style={{ position: "relative" }}>
          {icon && (
            <span
              style={{
                position: "absolute",
                left: 12,
                top: 13,
                color: "#5b6a86",
              }}
            >
              {icon}
            </span>
          )}
          <input
            ref={ref}
            className="field-input"
            style={{
              paddingLeft: icon ? 34 : undefined,
              ...style,
            }}
            {...props}
          />
        </div>
        {error && (
          <p style={{ marginTop: 4, fontSize: 11, color: "#f4536b", fontFamily: MONO }}>
            {error}
          </p>
        )}
        {hint && !error && (
          <p style={{ marginTop: 4, fontSize: 11, color: "#5b6a86", fontFamily: MONO }}>
            {hint}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";
export default Input;
