/**
 * EmptyState — Empty state matching the reference design.
 */
import { ReactNode } from "react";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";
const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface EmptyStateProps {
  icon?: string;
  title: string;
  description?: string;
  action?: ReactNode;
}

export default function EmptyState({ icon = "📭", title, description, action }: EmptyStateProps) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "64px 20px", textAlign: "center" }}>
      <span style={{ fontSize: 48, marginBottom: 16 }}>{icon}</span>
      <h3 style={{ fontFamily: DISPLAY, fontSize: 18, fontWeight: 700, color: "#e8edf7", marginBottom: 8 }}>{title}</h3>
      {description && <p style={{ color: "#8493ac", fontSize: 13, maxWidth: 400, marginBottom: 24, fontFamily: MONO }}>{description}</p>}
      {action}
    </div>
  );
}
