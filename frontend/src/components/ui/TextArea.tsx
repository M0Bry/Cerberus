/**
 * TextArea — Textarea matching the reference design.
 */
import { TextareaHTMLAttributes, forwardRef } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
}

const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(
  ({ label, error, style, ...props }, ref) => {
    return (
      <div style={{ marginBottom: 16 }}>
        {label && (
          <label style={{ display: "block", fontSize: 12.5, color: "#8493ac", marginBottom: 7, fontFamily: MONO }}>
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          className="field-input"
          style={{ minHeight: 100, resize: "vertical", ...style }}
          {...props}
        />
        {error && <p style={{ marginTop: 4, fontSize: 11, color: "#f4536b", fontFamily: MONO }}>{error}</p>}
      </div>
    );
  }
);
TextArea.displayName = "TextArea";
export default TextArea;
