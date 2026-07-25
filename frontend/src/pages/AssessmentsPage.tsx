/**
 * Assessments Page — List all engagements with search and filtering.
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import { engagementService } from "../services/engagement";

/* ------------------------------------------------------------------ */
/*  Local Types (mirror the expected API shapes)                       */
/* ------------------------------------------------------------------ */
type EngagementStatus =
  | "draft"
  | "scope_defined"
  | "rules_generated"
  | "authorized"
  | "initializing"
  | "osint_in_progress"
  | "osint_complete"
  | "attack_planning"
  | "attack_planning_complete"
  | "red_team_in_progress"
  | "red_team_complete"
  | "risk_assessment"
  | "risk_assessment_complete"
  | "report_generating"
  | "completed"
  | "cancelled";

interface Engagement {
  id: string;
  project_name: string;
  engagement_number: string;
  organization_name: string;
  status: EngagementStatus;
  progress_percentage: number;
  risk_level?: string;
  created_at: string;
}

interface EngagementListResponse {
  items: Engagement[];
  total: number;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */
const STATUS_FILTERS: { label: string; value: EngagementStatus | "" }[] = [
  { label: "All", value: "" },
  { label: "Draft", value: "draft" },
  { label: "OSINT", value: "osint_in_progress" },
  { label: "Red Team", value: "red_team_in_progress" },
  { label: "Completed", value: "completed" },
];

const STATUS_COLORS: Record<EngagementStatus, string> = {
  draft: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  scope_defined: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  rules_generated: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
  authorized: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  initializing: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  osint_in_progress: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  osint_complete: "bg-green-500/20 text-green-400 border-green-500/30",
  attack_planning: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  attack_planning_complete: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  red_team_in_progress: "bg-red-500/20 text-red-400 border-red-500/30",
  red_team_complete: "bg-rose-500/20 text-rose-400 border-rose-500/30",
  risk_assessment: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  risk_assessment_complete: "bg-fuchsia-500/20 text-fuchsia-400 border-fuchsia-500/30",
  report_generating: "bg-teal-500/20 text-teal-400 border-teal-500/30",
  completed: "bg-green-500/20 text-green-400 border-green-500/30",
  cancelled: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */
export default function AssessmentsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<EngagementStatus | "">("");
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery<EngagementListResponse>({
    queryKey: ["engagements", page, statusFilter, search],
    queryFn: (): Promise<EngagementListResponse> =>
      engagementService
        .list({
          page,
          page_size: 20,
          status: statusFilter || undefined,
          search: search || undefined,
        })
        .then((res: { data: EngagementListResponse }) => res.data),
  });

  return (
    <DashboardLayout activeItem="assessments">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-white">My Assessments</h1>
          <button
            onClick={() => navigate("/assessments/new")}
            className="btn-glow"
          >
            + New Assessment
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-4 items-center">
          <input
            type="text"
            placeholder="Search by name or ID..."
            className="cyber-input w-72"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
          <div className="flex gap-2">
            {STATUS_FILTERS.map((f) => (
              <button
                key={f.value}
                onClick={() => {
                  setStatusFilter(f.value);
                  setPage(1);
                }}
                className={`px-3 py-1.5 text-xs rounded-full border transition-all ${
                  statusFilter === f.value
                    ? "border-cerberus-blue text-cerberus-blue bg-cerberus-blue/10"
                    : "border-cerberus-gray-600 text-gray-400 hover:border-gray-500"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Assessment Cards */}
        {isLoading ? (
          <div className="cyber-card text-center text-gray-400 py-12">
            Loading assessments...
          </div>
        ) : data?.items?.length ? (
          <div className="space-y-3">
            {data.items.map((eng) => (
              <div
                key={eng.id}
                onClick={() => navigate(`/engagement/${eng.id}/operations`)}
                className="cyber-card flex items-center justify-between cursor-pointer"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <h3 className="text-white font-medium">
                      {eng.project_name}
                    </h3>
                    <span
                      className={`status-badge border ${
                        STATUS_COLORS[eng.status] ?? STATUS_COLORS.draft
                      }`}
                    >
                      {eng.status.replace(/_/g, " ")}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mt-1">
                    {eng.engagement_number} • {eng.organization_name}
                  </p>
                </div>

                <div className="flex items-center gap-6">
                  {/* Progress bar */}
                  <div className="w-32">
                    <div className="flex justify-between text-xs text-gray-400 mb-1">
                      <span>Progress</span>
                      <span>{eng.progress_percentage}%</span>
                    </div>
                    <div className="w-full h-2 bg-cerberus-gray-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cerberus-blue to-cerberus-accent rounded-full transition-all"
                        style={{ width: `${eng.progress_percentage}%` }}
                      />
                    </div>
                  </div>

                  {/* Risk level badge */}
                  {eng.risk_level && (
                    <span
                      className={`status-badge ${
                        eng.risk_level === "critical"
                          ? "status-critical"
                          : eng.risk_level === "high"
                          ? "status-high"
                          : eng.risk_level === "medium"
                          ? "status-medium"
                          : "status-low"
                      }`}
                    >
                      {eng.risk_level}
                    </span>
                  )}

                  <span className="text-sm text-gray-500">
                    {new Date(eng.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="cyber-card text-center py-16">
            <span className="text-5xl">🔍</span>
            <p className="text-gray-400 mt-4 text-lg">
              No assessments found
            </p>
            <p className="text-gray-500 text-sm mt-1">
              Start your first security assessment to see it here.
            </p>
          </div>
        )}

        {/* Pagination */}
        {data && data.total > 20 && (
          <div className="flex justify-center gap-2 mt-6">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-4 py-2 text-sm bg-cerberus-gray-800 border border-cerberus-gray-600
                         rounded-lg text-gray-300 disabled:opacity-50 hover:border-cerberus-blue transition-colors"
            >
              Previous
            </button>
            <span className="px-4 py-2 text-sm text-gray-400">
              Page {page} of {Math.ceil(data.total / 20)}
            </span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page >= Math.ceil(data.total / 20)}
              className="px-4 py-2 text-sm bg-cerberus-gray-800 border border-cerberus-gray-600
                         rounded-lg text-gray-300 disabled:opacity-50 hover:border-cerberus-blue transition-colors"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
