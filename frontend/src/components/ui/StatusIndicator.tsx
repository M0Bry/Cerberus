/**
 * StatusIndicator — Status dot matching the reference design.
 */
type Status = "online" | "offline" | "pending" | "active" | "error";

const colorMap: Record<Status, string> = {
  online: "#34e0a1",
  offline: "#5b6a86",
  pending: "#e0b93a",
  active: "#2f7dfa",
  error: "#f4536b",
};

export default function StatusIndicator({ status, label }: { status: Status; label?: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: colorMap[status],
          boxShadow: status === "active" ? `0 0 8px ${colorMap[status]}` : "none",
          animation: status === "active" ? "pulseRing 1.8s infinite" : "none",
        }}
      />
      {label && <span style={{ fontSize: 11, color: "#8493ac" }}>{label}</span>}
    </span>
  );
}
