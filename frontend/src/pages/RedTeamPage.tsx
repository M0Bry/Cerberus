/**
 * RedTeamPage — Uses redTeamStore for local state + TanStack Query for server data.
 */

import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import DashboardLayout from "../components/layout/DashboardLayout";
import RedTeamDashboard from "../components/redteam/RedTeamDashboard";
import { redTeamApi } from "../api/redTeamApi";
import { useRedTeamStore } from "../stores/redTeamStore";

/* ------------------------------------------------------------------ */
/*  Types (mirror the store's Vuln shape)                              */
/* ------------------------------------------------------------------ */

interface Vuln {
  id: string;
  title: string;
  severity: string;
  status: string;
  affected_assets: string;
}

interface RedTeamStatusResponse {
  status: string;
  total_paths?: number;
  completed_paths?: number;
  confirmed_vulnerabilities?: number;
  progress_percentage?: number;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function RedTeamPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const { findings, setStatus, setFindings } = useRedTeamStore();

  // Fetch status
  const { data: status } = useQuery<RedTeamStatusResponse>({
    queryKey: ["redTeamStatus", engagementId],
    queryFn: () =>
      redTeamApi
        .getStatus(engagementId!)
        .then((res: { data: RedTeamStatusResponse }) => res.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // Fetch vulnerabilities and convert to Vuln[]
  const { data: vulns } = useQuery<Vuln[]>({
    queryKey: ["redTeamVulns", engagementId],
    queryFn: () =>
      redTeamApi
        .getVulnerabilities(engagementId!)
        .then(
          (
            res: {
              data: { id: string; title: string; severity: string }[];
            },
          ) =>
            res.data.map((item) => ({
              id: item.id,
              title: item.title,
              severity: item.severity,
              status: "confirmed",
              affected_assets: "",
            })),
        ),
    enabled: !!engagementId,
  });

  // Sync into store
  useEffect(() => {
    if (status) {
      // Store's setStatus expects a specific union type; `as any` is a temporary
      // workaround until the store's status type is corrected.
      setStatus(status.status as any);
    }
    if (vulns) setFindings(vulns);
  }, [status, vulns, setStatus, setFindings]);

  return (
    <DashboardLayout>
      <h1 className="text-3xl font-bold text-white mb-6">Red Team Operations</h1>
      {/* ✅ Now correctly typed – no more error */}
      <RedTeamDashboard engagementId={engagementId} />

      {findings.length > 0 && (
        <div className="mt-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Confirmed Vulnerabilities ({findings.length})
          </h2>
          <div className="space-y-2">
            {findings.map((v) => (
              <div key={v.id} className="cyber-card flex items-center justify-between">
                <div>
                  <p className="text-sm text-white font-medium">{v.title}</p>
                  <p className="text-xs text-gray-400">{v.affected_assets}</p>
                </div>
                <span
                  className={`px-2 py-0.5 text-xs rounded-full ${
                    v.severity === "critical"
                      ? "bg-red-500/20 text-red-400"
                      : v.severity === "high"
                      ? "bg-orange-500/20 text-orange-400"
                      : "bg-yellow-500/20 text-yellow-400"
                  }`}
                >
                  {v.severity.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
