/**
 * Select — Dropdown select matching the reference design.
 */
import { SelectHTMLAttributes, forwardRef } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  options: Array<{ value: string; label: string }>;
}

const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, options, style, ...props }, ref) => {
    return (
      <div style={{ marginBottom: 16 }}>
        {label && (
          <label style={{ display: "block", fontSize: 12.5, color: "#8493ac", marginBottom: 7, fontFamily: MONO }}>
            {label}
          </label>
        )}
        <select
          ref={ref}
          className="field-input"
          style={{ ...style }}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
        {error && <p style={{ marginTop: 4, fontSize: 11, color: "#f4536b", fontFamily: MONO }}>{error}</p>}
      </div>
    );
  }
);
Select.displayName = "Select";
export default Select;
