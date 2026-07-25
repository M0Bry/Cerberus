/**
 * ProgressBar — Progress bar matching the exact reference design.
 */

interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  showPercentage?: boolean;
  color?: "blue" | "green" | "yellow" | "red";
  height?: number;
}

const colorMap = {
  blue: "linear-gradient(90deg, #2f7dfa, #22d3ee)",
  green: "linear-gradient(90deg, #34e0a1, #22d3ee)",
  yellow: "linear-gradient(90deg, #e0b93a, #ff8a3d)",
  red: "linear-gradient(90deg, #f4536b, #ff8a3d)",
};

export default function ProgressBar({
  value, max = 100, label, showPercentage = true, color = "blue", height = 5,
}: ProgressBarProps) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));

  return (
    <div style={{ width: "100%" }}>
      {(label || showPercentage) && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
          {label && <span style={{ fontSize: 10.5, color: "#5b6a86" }}>{label}</span>}
          {showPercentage && <span style={{ fontSize: 10.5, color: "#5b6a86" }}>{Math.round(pct)}%</span>}
        </div>
      )}
      <div
        style={{
          width: "100%",
          height,
          borderRadius: 4,
          background: "rgba(255,255,255,0.06)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: "100%",
            background: colorMap[color],
            borderRadius: 4,
            transition: "width 1s ease",
          }}
        />
      </div>
    </div>
  );
}
