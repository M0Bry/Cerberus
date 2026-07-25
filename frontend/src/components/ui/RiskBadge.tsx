/**
 * RiskBadge — Risk level badge matching the exact reference design.
 */

type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

interface RiskBadgeProps {
  level: RiskLevel;
  size?: "sm" | "md";
}

const styles: Record<RiskLevel, { color: string; bg: string; border: string }> = {
  critical: { color: "#f4536b", bg: "rgba(244,83,107,0.15)", border: "rgba(244,83,107,0.4)" },
  high: { color: "#ff8a3d", bg: "rgba(255,138,61,0.15)", border: "rgba(255,138,61,0.4)" },
  medium: { color: "#e0b93a", bg: "rgba(224,185,58,0.15)", border: "rgba(224,185,58,0.4)" },
  low: { color: "#34e0a1", bg: "rgba(52,224,161,0.15)", border: "rgba(52,224,161,0.4)" },
  info: { color: "#22d3ee", bg: "rgba(34,211,238,0.15)", border: "rgba(34,211,238,0.4)" },
};

export default function RiskBadge({ level, size = "sm" }: RiskBadgeProps) {
  const s = styles[level];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: size === "sm" ? "4px 10px" : "6px 14px",
        fontSize: size === "sm" ? 11 : 13,
        fontWeight: 700,
        fontFamily: "'Share Tech Mono', monospace",
        borderRadius: 999,
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
      }}
    >
      {level.toUpperCase()}
    </span>
  );
}
