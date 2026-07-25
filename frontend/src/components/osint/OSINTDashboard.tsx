/**
 * OSINTDashboard — Main OSINT operations dashboard.
 * Displays overview, status, progress, and category-specific findings.
 */

import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import Card from "../ui/Card";
import CountUp from "../ui/CountUp";
import { osintApi } from "../../api/osintApi";

interface OSINTSummary {
  total_findings: number;
  domains_discovered: number;
  technologies_identified: number;
  employee_profiles: number;
  leaked_credentials: number;
  archived_resources: number;
  risk_distribution?: Record<string, number>;
}

interface OSINTFinding {
  id: string;
  category: string;
  title: string;
  description: string;
  confidence_score: number;
}

interface KnowledgeGraph {
  nodes: unknown[];
  edges: unknown[];
}

const CATEGORY_COLORS: Record<string, string> = {
  technical: "border-cerberus-blue bg-cerberus-blue/5",
  credential: "border-cerberus-red bg-cerberus-red/5",
  employee: "border-cerberus-yellow bg-cerberus-yellow/5",
  technology: "border-cerberus-cyan bg-cerberus-cyan/5",
  historical_web: "border-cerberus-green bg-cerberus-green/5",
};

const CATEGORY_LABELS: Record<string, string> = {
  technical: "Technical",
  credential: "Credentials",
  employee: "Employees",
  technology: "Technology",
  historical_web: "Historical",
};

export default function OSINTDashboard({ engagementId }: { engagementId?: string }) {
  const { id } = useParams();
  const eid = engagementId ?? id;

  const { data: summary } = useQuery<OSINTSummary>({
    queryKey: ["osintSummary", eid],
    queryFn: () => osintApi.getSummary(eid!).then((r) => r.data),
    enabled: !!eid,
    refetchInterval: 5000,
  });

  const { data: findings, isLoading: findingsLoading } = useQuery<{ items: OSINTFinding[] }>({
    queryKey: ["osintFindings", eid],
    queryFn: () => osintApi.getFindings(eid!, { page_size: 100 }).then((r) => r.data),
    enabled: !!eid,
    refetchInterval: 5000,
  });

  const { data: graph } = useQuery<KnowledgeGraph>({
    queryKey: ["osintGraph", eid],
    queryFn: () => osintApi.getKnowledgeGraph(eid!).then((r) => r.data),
    enabled: !!eid,
  });

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        {[
          { label: "Total Findings", value: summary?.total_findings ?? 0, color: "text-cerberus-blue" },
          { label: "Domains", value: summary?.domains_discovered ?? 0, color: "text-cerberus-blue" },
          { label: "Technologies", value: summary?.technologies_identified ?? 0, color: "text-cerberus-cyan" },
          { label: "Employees", value: summary?.employee_profiles ?? 0, color: "text-cerberus-yellow" },
          { label: "Credentials", value: summary?.leaked_credentials ?? 0, color: "text-cerberus-red" },
          { label: "Archives", value: summary?.archived_resources ?? 0, color: "text-cerberus-green" },
        ].map((stat) => (
          <Card key={stat.label} className="text-center">
            <CountUp target={stat.value} className={`text-2xl font-bold ${stat.color}`} />
            <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
          </Card>
        ))}
      </div>

      {/* Risk Distribution */}
      {summary?.risk_distribution && (
        <Card>
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Risk Distribution by Category
          </h3>
          <div className="grid grid-cols-5 gap-4">
            {Object.entries(summary.risk_distribution).map(([cat, count]) => (
              <div key={cat} className="text-center">
                <p className="text-lg font-bold text-white mt-1">{count}</p>
                <p className="text-xs text-gray-400">
                  {CATEGORY_LABELS[cat] ?? cat}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Knowledge Graph Summary */}
      {graph && (
        <Card>
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
            Knowledge Graph
          </h3>
          <div className="flex gap-8">
            <div>
              <span className="text-2xl font-bold text-cerberus-blue">
                {graph.nodes?.length ?? 0}
              </span>
              <p className="text-xs text-gray-400">Nodes</p>
            </div>
            <div>
              <span className="text-2xl font-bold text-cerberus-accent">
                {graph.edges?.length ?? 0}
              </span>
              <p className="text-xs text-gray-400">Connections</p>
            </div>
          </div>
        </Card>
      )}

      {/* Live Findings Feed */}
      <div>
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span className="w-2 h-2 bg-cerberus-green rounded-full animate-pulse" />
          Live Intelligence Feed
        </h3>

        {findingsLoading ? (
          <Card className="text-center text-gray-400 py-8">Loading findings...</Card>
        ) : findings?.items?.length ? (
          <div className="space-y-3">
            {findings.items.map((finding) => (
              <div
                key={finding.id}
                className={`p-4 rounded-lg border-l-4 ${
                  CATEGORY_COLORS[finding.category] ?? CATEGORY_COLORS.technical
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono uppercase text-gray-400">
                      {finding.category}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-cerberus-blue">
                      Confidence: {((finding.confidence_score ?? 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
                <h4 className="text-white font-medium text-sm">{finding.title}</h4>
                <p className="text-gray-400 text-xs mt-1">{finding.description}</p>
              </div>
            ))}
          </div>
        ) : (
          <Card className="text-center py-12 text-gray-500">
            <p>Waiting for intelligence discoveries...</p>
          </Card>
        )}
      </div>
    </div>
  );
}
