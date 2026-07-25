/**
 * Badge — Status badge matching the exact reference design.
 */

type Variant = "default" | "success" | "warning" | "danger" | "info";

interface BadgeProps {
  children: React.ReactNode;
  variant?: Variant;
  size?: "sm" | "md";
}

const variantStyles: Record<Variant, { bg: string; color: string; border: string }> = {
  default: { bg: "rgba(255,255,255,0.06)", color: "#8493ac", border: "#152238" },
  success: { bg: "rgba(52,224,161,0.15)", color: "#34e0a1", border: "rgba(52,224,161,0.3)" },
  warning: { bg: "rgba(224,185,58,0.15)", color: "#e0b93a", border: "rgba(224,185,58,0.3)" },
  danger: { bg: "rgba(244,83,107,0.15)", color: "#f4536b", border: "rgba(244,83,107,0.3)" },
  info: { bg: "rgba(47,125,250,0.15)", color: "#2f7dfa", border: "rgba(47,125,250,0.3)" },
};

export default function Badge({ children, variant = "default", size = "sm" }: BadgeProps) {
  const s = variantStyles[variant];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: size === "sm" ? "4px 10px" : "6px 14px",
        fontSize: size === "sm" ? 10.5 : 12,
        fontWeight: 700,
        fontFamily: "'Share Tech Mono', monospace",
        borderRadius: 999,
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        letterSpacing: 0.5,
      }}
    >
      {children}
    </span>
  );
}
