/**
 * Operations Page — Live Security Operations Dashboard.
 *
 * Real-time monitoring of all assessment phases with
 * color-coded finding cards and progress tracking.
 */

import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { engagementService } from "../services/engagement";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Engagement {
  id: string;
  organization_name: string;
  engagement_number: string;
  status: string;
  progress_percentage: number;
}

interface OSINTFinding {
  id: string;
  category: string;
  title: string;
  description: string;
  confidence_score: number;
}

interface OSINTFindingsResponse {
  items: OSINTFinding[];
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const PHASE_LABELS: Record<string, string> = {
  draft: "Draft",
  scope_defined: "Scope Defined",
  authorized: "Authorized",
  initializing: "Initializing...",
  osint_in_progress: "Phase 1: OSINT Collection",
  osint_complete: "OSINT Complete",
  attack_planning: "Phase 2: Attack Planning",
  red_team_in_progress: "Phase 2: Red Team Execution",
  red_team_complete: "Red Team Complete",
  risk_assessment: "Phase 3: Risk Assessment",
  risk_assessment_complete: "Risk Assessment Complete",
  report_generating: "Phase 4: Report Generation",
  completed: "Assessment Complete",
};

const FINDING_CARD_COLORS: Record<string, string> = {
  technical: "border-cerberus-blue bg-cerberus-blue/5",
  credential: "border-cerberus-red bg-cerberus-red/5",
  employee: "border-cerberus-yellow bg-cerberus-yellow/5",
  technology: "border-cerberus-cyan bg-cerberus-cyan/5",
  historical_web: "border-cerberus-green bg-cerberus-green/5",
};

const PHASES = [
  "osint_in_progress",
  "attack_planning",
  "red_team_in_progress",
  "risk_assessment",
  "report_generating",
  "completed",
] as const;

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function OperationsPage() {
  const { id: engagementId } = useParams<{ id: string }>();

  const { data: engagement } = useQuery<Engagement>({
    queryKey: ["engagement", engagementId],
    queryFn: () =>
      engagementService
        .get(engagementId!)
        .then((res: { data: Engagement }) => res.data),
    enabled: !!engagementId,
  });

  const { data: osintFindings } = useQuery<OSINTFindingsResponse>({
    queryKey: ["osint-findings", engagementId],
    queryFn: () =>
      engagementService
        .getOSINTFindings(engagementId!)
        .then((res: { data: OSINTFindingsResponse }) => res.data),
    enabled: !!engagementId,
    refetchInterval: 5000, // Poll every 5 seconds for live updates
  });

  const eng = engagement;

  return (
    <div className="min-h-screen bg-cerberus-dark">
      {/* ─── Status Bar ─────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-cerberus-gray-900/90 backdrop-blur-sm border-b border-cerberus-gray-700 px-6 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-6">
            <span className="text-xl">🛡️</span>
            <div>
              <h1 className="text-white font-bold text-sm">
                {eng?.organization_name || "Loading..."}
              </h1>
              <span className="text-xs text-gray-400 font-mono">
                {eng?.engagement_number || "—"}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-8 text-sm">
            <div>
              <span className="text-gray-400">Phase: </span>
              <span className="text-cerberus-blue font-mono">
                {PHASE_LABELS[eng?.status ?? ""] || eng?.status || "—"}
              </span>
            </div>
            <div>
              <span className="text-gray-400">Progress: </span>
              <span className="text-white font-mono">
                {eng?.progress_percentage ?? 0}%
              </span>
            </div>
            <div>
              <span className="text-gray-400">Status: </span>
              <span className="text-cerberus-green">● Active</span>
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div className="max-w-7xl mx-auto mt-2">
          <div className="w-full h-1.5 bg-cerberus-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cerberus-blue via-cerberus-accent to-cerberus-green
                         rounded-full transition-all duration-1000"
              style={{ width: `${eng?.progress_percentage ?? 0}%` }}
            />
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* ─── Phase Progress Indicators ────────────────── */}
        <div className="flex items-center gap-4 mb-8 overflow-x-auto pb-2">
          {PHASES.map((phase, i) => {
            const isActive = eng?.status === phase;
            const currentIndex = PHASES.indexOf(eng?.status as typeof PHASES[number]);
            const isPast = currentIndex !== -1 && currentIndex > i;

            return (
              <div
                key={phase}
                className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs whitespace-nowrap transition-all ${
                  isActive
                    ? "bg-cerberus-blue/20 text-cerberus-blue border border-cerberus-blue/40"
                    : isPast
                    ? "bg-cerberus-green/10 text-cerberus-green border border-cerberus-green/30"
                    : "bg-cerberus-gray-800 text-gray-500 border border-cerberus-gray-700"
                }`}
              >
                <span>
                  {isPast ? "✓" : isActive ? "●" : "○"}
                </span>
                {PHASE_LABELS[phase]?.replace(/Phase \d: /, "") || phase}
              </div>
            );
          })}
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* ─── Live Operations Feed ─────────────────────── */}
          <div className="col-span-2 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <span className="w-2 h-2 bg-cerberus-green rounded-full animate-pulse" />
              Live Operations Feed
            </h2>

            {osintFindings?.items?.length ? (
              osintFindings.items.map((finding) => (
                <div
                  key={finding.id}
                  className={`p-4 rounded-lg border-l-4 ${
                    FINDING_CARD_COLORS[finding.category] ||
                    FINDING_CARD_COLORS.technical
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono uppercase text-gray-400">
                      {finding.category}
                    </span>
                    <span className="text-xs text-gray-500">
                      Confidence: {(finding.confidence_score * 100).toFixed(0)}%
                    </span>
                  </div>
                  <h3 className="text-white font-medium text-sm">
                    {finding.title}
                  </h3>
                  <p className="text-gray-400 text-xs mt-1">
                    {finding.description}
                  </p>
                </div>
              ))
            ) : (
              <div className="cyber-card text-center py-12 text-gray-500">
                <span className="text-3xl block mb-2">📡</span>
                {eng?.status === "draft" || eng?.status === "authorized"
                  ? "Assessment not yet started. Begin the AI conversation to initialize."
                  : "Waiting for intelligence discoveries..."}
              </div>
            )}
          </div>

          {/* ─── Right Panel — Stats & Actions ───────────── */}
          <div className="space-y-6">
            {/* Quick Actions */}
            <div className="cyber-card">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
                Actions
              </h3>
              <div className="space-y-2">
                {eng?.status === "authorized" && (
                  <button className="btn-glow w-full text-sm text-center">
                    🚀 Begin Assessment
                  </button>
                )}
                {eng?.status === "osint_complete" && (
                  <button className="btn-glow w-full text-sm text-center">
                    🗺️ Start Attack Planning
                  </button>
                )}
                {eng?.status === "red_team_complete" && (
                  <button className="btn-glow w-full text-sm text-center">
                    📊 Start Risk Assessment
                  </button>
                )}
                {eng?.status === "risk_assessment_complete" && (
                  <button className="btn-glow w-full text-sm text-center">
                    📄 Generate Report
                  </button>
                )}
                <button className="w-full text-sm text-left px-4 py-2 text-gray-400 hover:text-white
                                   bg-cerberus-gray-900 rounded-lg transition-colors">
                  📋 View Scope
                </button>
                <button className="w-full text-sm text-left px-4 py-2 text-gray-400 hover:text-white
                                   bg-cerberus-gray-900 rounded-lg transition-colors">
                  📜 Rules of Engagement
                </button>
              </div>
            </div>

            {/* Knowledge Graph Summary */}
            <div className="cyber-card">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
                Knowledge Graph
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Nodes</span>
                  <span className="text-cerberus-blue font-mono">0</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Connections</span>
                  <span className="text-cerberus-blue font-mono">0</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Attack Paths</span>
                  <span className="text-cerberus-blue font-mono">0</span>
                </div>
              </div>
            </div>

            {/* Finding Categories */}
            <div className="cyber-card">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
                Finding Categories
              </h3>
              <div className="space-y-2">
                {[
                  { color: "bg-cerberus-blue", label: "Technical", count: 0 },
                  { color: "bg-cerberus-red", label: "Credentials", count: 0 },
                  { color: "bg-cerberus-yellow", label: "Employees", count: 0 },
                  { color: "bg-cerberus-cyan", label: "Technology", count: 0 },
                  { color: "bg-cerberus-green", label: "Historical", count: 0 },
                ].map((cat) => (
                  <div
                    key={cat.label}
                    className="flex items-center justify-between text-sm"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-3 h-3 rounded-full ${cat.color}`}
                      />
                      <span className="text-gray-400">{cat.label}</span>
                    </div>
                    <span className="text-white font-mono">{cat.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
