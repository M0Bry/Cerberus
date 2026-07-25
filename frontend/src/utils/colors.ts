/**
 * Colors — Color scheme mapping for the Cerberus design system.
 */

export const C = {
  bg: "#03060c",
  panel: "rgba(10,16,28,0.7)",
  panelSolid: "#0a101c",
  border: "#152238",
  borderStrong: "rgba(56,142,255,0.45)",
  text: "#e8edf7",
  muted: "#8493ac",
  dim: "#5b6a86",
  blue: "#2f7dfa",
  cyan: "#22d3ee",
  green: "#34e0a1",
  red: "#f4536b",
  yellow: "#e0b93a",
} as const;

export function riskColor(risk: string): string {
  return { Low: C.green, Medium: C.yellow, High: "#ff8a3d", Critical: C.red }[risk] || C.muted;
}
