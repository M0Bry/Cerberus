/**
 * SeverityChip — Severity chip matching the reference design.
 */
const styleMap: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#f4536b", bg: "rgba(244,83,107,0.15)", border: "rgba(244,83,107,0.3)" },
  high: { color: "#ff8a3d", bg: "rgba(255,138,61,0.15)", border: "rgba(255,138,61,0.3)" },
  medium: { color: "#e0b93a", bg: "rgba(224,185,58,0.15)", border: "rgba(224,185,58,0.3)" },
  low: { color: "#34e0a1", bg: "rgba(52,224,161,0.15)", border: "rgba(52,224,161,0.3)" },
  info: { color: "#22d3ee", bg: "rgba(34,211,238,0.15)", border: "rgba(34,211,238,0.3)" },
};

export default function SeverityChip({ severity }: { severity: string }) {
  const s = styleMap[severity] || styleMap.info;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "3px 8px",
        fontSize: 10,
        fontWeight: 700,
        fontFamily: "'Share Tech Mono', monospace",
        borderRadius: 6,
        background: s.bg,
        color: s.color,
        border: `1px solid ${s.border}`,
        letterSpacing: 0.5,
      }}
    >
      {severity.toUpperCase()}
    </span>
  );
}
