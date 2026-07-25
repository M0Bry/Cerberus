/**
 * PasswordInput — Password field with toggle matching the reference design.
 */
import { useState, forwardRef, InputHTMLAttributes } from "react";
import { Eye, EyeOff } from "lucide-react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface PasswordInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(
  ({ label, error, style, ...props }, ref) => {
    const [visible, setVisible] = useState(false);

    return (
      <div style={{ marginBottom: 16 }}>
        {label && (
          <label style={{ display: "block", fontSize: 12.5, color: "#8493ac", marginBottom: 7, fontFamily: MONO }}>
            {label}
          </label>
        )}
        <div style={{ position: "relative" }}>
          <input
            ref={ref}
            type={visible ? "text" : "password"}
            className="field-input"
            style={{ paddingRight: 38, ...style }}
            {...props}
          />
          <span
            onClick={() => setVisible(!visible)}
            style={{ position: "absolute", right: 12, top: 12, cursor: "pointer", color: "#5b6a86" }}
          >
            {visible ? <EyeOff size={15} /> : <Eye size={15} />}
          </span>
        </div>
        {error && <p style={{ marginTop: 4, fontSize: 11, color: "#f4536b", fontFamily: MONO }}>{error}</p>}
      </div>
    );
  }
);
PasswordInput.displayName = "PasswordInput";
export default PasswordInput;
