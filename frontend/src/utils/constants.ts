/**
 * Constants — App constants matching the reference design.
 */

export const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";
export const MONO = "'Share Tech Mono', 'Courier New', monospace";

export const COLORS = {
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

export const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"] as const;

export const ENGAGEMENT_STATUSES = [
  "draft", "scope_defined", "authorized", "osint_in_progress", "osint_complete",
  "attack_planning", "red_team_in_progress", "risk_assessment", "report_generating", "completed",
] as const;

export const PHASE_LABELS: Record<string, string> = {
  draft: "Draft",
  scope_defined: "Scope Defined",
  authorized: "Authorized",
  osint_in_progress: "Phase 1: OSINT",
  osint_complete: "OSINT Complete",
  attack_planning: "Phase 2: Attack Planning",
  red_team_in_progress: "Phase 2: Red Team",
  risk_assessment: "Phase 3: Risk Assessment",
  report_generating: "Phase 4: Report Generation",
  completed: "Completed",
};
