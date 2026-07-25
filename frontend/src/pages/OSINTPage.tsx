/**
 * OSINT Page — Uses osintStore for local state + TanStack Query for server data.
 */

import { useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import DashboardLayout from "../components/layout/DashboardLayout";
import OSINTDashboard from "../components/osint/OSINTDashboard";
import OSINTExportButton from "../components/osint/OSINTExportButton";
import Button from "../components/ui/Button";
import Card from "../components/ui/Card";
import { osintApi } from "../api/osintApi";
import { engagementService } from "../services/engagement";
import { useOSINTStore } from "../stores/osintStore";
import type { OSINTSummary, OSINTFinding } from "../types/osint.types";

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const MODULES = [
  { name: "Domain Intel", icon: "🌐", key: "domain_intel" },
  { name: "Social Scanner", icon: "📱", key: "social_scanner" },
  { name: "Username Enum", icon: "👤", key: "username_enum" },
  { name: "GitHub Scanner", icon: "💻", key: "github_scan" },
  { name: "DNS Records", icon: "📡", key: "dns_lookup" },
  { name: "Certificate Transparency", icon: "🔒", key: "ct_lookup" },
  { name: "Web Archives", icon: "📚", key: "web_archive" },
  { name: "Technology Fingerprint", icon: "🔍", key: "tech_fingerprint" },
];

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function OSINTPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { setFindings, setSummary } = useOSINTStore();

  // Engagement (basic info needed only for project name)
  const { data: engagement } = useQuery<{ project_name: string }>({
    queryKey: ["engagement", engagementId],
    queryFn: () =>
      engagementService
        .get(engagementId!)
        .then((res: { data: { project_name: string } }) => res.data),
    enabled: !!engagementId,
  });

  // OSINT Summary
  const { data: summaryData } = useQuery<OSINTSummary>({
    queryKey: ["osintSummary", engagementId],
    queryFn: () =>
      osintApi
        .getSummary(engagementId!)
        .then((res: { data: OSINTSummary }) => res.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // OSINT Findings
  const { data: findingsData } = useQuery<{ items: OSINTFinding[] }>({
    queryKey: ["osintFindings", engagementId],
    queryFn: () =>
      osintApi
        .getFindings(engagementId!, { page_size: 200 })
        .then((res: { data: { items: OSINTFinding[] } }) => res.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // Sync server data into store
  useEffect(() => {
    if (summaryData) setSummary(summaryData);
  }, [summaryData, setSummary]);

  useEffect(() => {
    if (findingsData?.items) setFindings(findingsData.items);
  }, [findingsData, setFindings]);

  const startMutation = useMutation({
    mutationFn: () => osintApi.startOSINT(engagementId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["osintSummary", engagementId] });
      qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] });
    },
  });

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">OSINT Operations</h1>
            <p className="text-gray-400 mt-1">
              Phase 1: Open-Source Intelligence — {engagement?.project_name || "Loading..."}
            </p>
          </div>
          <div className="flex gap-3">
            <OSINTExportButton engagementId={engagementId!} />
            <Button onClick={() => navigate(`/redteam/${engagementId}`)}>
              Next: Red Team →
            </Button>
          </div>
        </div>

        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
              Collection Modules
            </h3>
            <Button
              variant="primary"
              size="sm"
              onClick={() => startMutation.mutate()}
              loading={startMutation.isPending}
            >
              🚀 Start Collection
            </Button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {MODULES.map((mod) => (
              <div
                key={mod.key}
                className="p-3 bg-cerberus-gray-900 rounded-lg border border-cerberus-gray-700 hover:border-cerberus-blue/40 transition-all"
              >
                <div className="flex items-center gap-2">
                  <span className="text-lg">{mod.icon}</span>
                  <span className="text-xs text-gray-300 font-medium">{mod.name}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Store-backed summary stats – using the real OSINTSummary fields */}
        {summaryData && (
          <div className="grid grid-cols-6 gap-4">
            {[
              { label: "Total", value: summaryData.total_findings },
              { label: "Domains", value: summaryData.domains_discovered },
              { label: "Tech", value: summaryData.technologies_identified },
              { label: "Employees", value: summaryData.employee_profiles },
              { label: "Credentials", value: summaryData.leaked_credentials },
              { label: "Archives", value: summaryData.archived_resources },
            ].map((s) => (
              <Card key={s.label} className="text-center">
                <p className="text-2xl font-bold text-cerberus-blue">{s.value}</p>
                <p className="text-xs text-gray-400 mt-1">{s.label}</p>
              </Card>
            ))}
          </div>
        )}

        <OSINTDashboard engagementId={engagementId} />
      </div>
    </DashboardLayout>
  );
}
