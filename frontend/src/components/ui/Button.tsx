/**
 * Button — CTA button matching the exact reference design.
 */
import { ButtonHTMLAttributes, forwardRef, ReactNode } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
}

const sizeStyles: Record<Size, React.CSSProperties> = {
  sm: { padding: "8px 16px", fontSize: 12 },
  md: { padding: "13px 26px", fontSize: 14.5 },
  lg: { padding: "16px 32px", fontSize: 16 },
};

const secondaryStyle: React.CSSProperties = {
  background: "transparent",
  color: "#22d3ee",
  border: "1px solid #152238",
  borderRadius: 8,
  fontFamily: MONO,
  fontWeight: 700,
  cursor: "pointer",
  transition: "border-color 0.2s",
};

const spinnerStyle: React.CSSProperties = {
  width: 16,
  height: 16,
  border: "2px solid rgba(255,255,255,0.3)",
  borderTopColor: "white",
  borderRadius: "50%",
  animation: "spin 1s linear infinite",
  display: "inline-block",
};

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = "primary",
      size = "md",
      loading,
      icon,
      children,
      style,
      disabled,
      ...props
    },
    ref,
  ) => {
    const isPrimary = variant === "primary";

    const baseStyle: React.CSSProperties = isPrimary
      ? {
          color: "white",
          border: "none",
          borderRadius: 8,
          fontFamily: MONO,
          fontWeight: 700,
          cursor: disabled || loading ? "not-allowed" : "pointer",
          opacity: disabled || loading ? 0.45 : 1,
          display: "flex",
          alignItems: "center",
          gap: 8,
          ...sizeStyles[size],
          ...style,
        }
      : {
          ...secondaryStyle,
          ...sizeStyles[size],
          opacity: disabled || loading ? 0.5 : 1,
          display: "flex",
          alignItems: "center",
          gap: 8,
          ...style,
        };

    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={isPrimary ? "cta-btn sheen" : ""}
        style={baseStyle}
        {...props}
      >
        {loading ? (
          <span style={spinnerStyle} />
        ) : icon ? (
          icon
        ) : null}
        {children}
      </button>
    );
  },
);

Button.displayName = "Button";
export default Button;
