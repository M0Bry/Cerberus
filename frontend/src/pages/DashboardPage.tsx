/**
 * Dashboard Page — Uses useEngagement + useSystemHealth hooks.
 */

import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import DashboardLayout from "../components/layout/DashboardLayout";
import CountUp from "../components/ui/CountUp";
import ProgressBar from "../components/ui/ProgressBar";
import RiskBadge from "../components/ui/RiskBadge";
import { useSystemHealth } from "../hooks/useSystemHealth";
import { dashboardService } from "../services/dashboard";
import { useAuthStore } from "../stores/authStore";
import { useQuery } from "@tanstack/react-query";

/* ------------------------------------------------------------------ */
/*  Local types                                                        */
/* ------------------------------------------------------------------ */

interface DashboardStat {
  label: string;
  value: number;
}

interface RecentAssessment {
  id: string;
  engagement_number: string;
  project_name: string;
  organization_name: string;
  status: string;
  progress_percentage: number;
  risk_level?: string;
  created_at: string;
}

interface DashboardOverview {
  success?: boolean;
  user_name?: string;
  organization_name?: string;
  stats?: DashboardStat[];
  recent_assessments?: RecentAssessment[];
  last_assessment_date?: string;
}

/* ------------------------------------------------------------------ */
/*  Helper                                                             */
/* ------------------------------------------------------------------ */

// RiskBadge expects "low" | "medium" | "high" | "critical"
function toRiskLevel(level?: string): "low" | "medium" | "high" | "critical" {
  if (level === "low" || level === "medium" || level === "high" || level === "critical") {
    return level;
  }
  return "low"; // safe fallback
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function DashboardPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);

  const { data: health } = useSystemHealth();

  const { data: overview, isLoading } = useQuery<DashboardOverview>({
    queryKey: ["dashboard-overview"],
    queryFn: () =>
      dashboardService.getOverview().then((r: { data: DashboardOverview }) => r.data),
  });

  const statsCards: { label: string; value: number; icon: string }[] = [
    { label: "Total Assessments", value: overview?.stats?.find(s => s.label === "Total Assessments")?.value ?? 0, icon: "📊" },
    { label: "Completed", value: overview?.stats?.find(s => s.label === "Completed")?.value ?? 0, icon: "✅" },
    { label: "Running", value: overview?.stats?.find(s => s.label === "Running")?.value ?? 0, icon: "⚡" },
    { label: "Reports", value: overview?.stats?.find(s => s.label === "Reports")?.value ?? 0, icon: "📄" },
    { label: "Critical Vulns", value: overview?.stats?.find(s => s.label === "Critical Vulns")?.value ?? 0, icon: "🔴" },
  ];

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Welcome back, <span className="text-gradient">{user?.full_name || "Commander"}</span>
          </h1>
          <p className="text-gray-400 mt-1">
            {user?.company_name ? `${user.company_name} • ` : ""}Manage your security assessments and monitor your organization's security posture.
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {statsCards.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="cyber-card text-center"
            >
              <span className="text-2xl">{stat.icon}</span>
              <CountUp target={stat.value} className="text-3xl font-bold text-cerberus-blue mt-2 glow-text block" />
              <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
            </motion.div>
          ))}
        </div>

        {/* System health indicator */}
        {health && (
          <div className="cyber-card flex items-center gap-3">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span className="text-sm text-gray-400">
              System Health:{" "}
              <span className="text-green-400 font-medium">
                {(health as { status?: string }).status || "Healthy"}
              </span>
            </span>
          </div>
        )}

        <div className="flex justify-between items-center">
          <h2 className="text-xl font-semibold text-white">My Assessments</h2>
          <button onClick={() => navigate("/chat")} className="btn-glow">
            + New Assessment
          </button>
        </div>

        <div className="flex gap-4">
          <input type="text" placeholder="Search by name, ID, or organization..." className="cyber-input w-80" />
        </div>

        <div className="space-y-3">
          {isLoading ? (
            <div className="cyber-card text-center text-gray-400 py-12">Loading assessments...</div>
          ) : overview?.recent_assessments?.length ? (
            overview.recent_assessments.map((eng) => (
              <motion.div
                key={eng.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                onClick={() => navigate(`/osint/${eng.id}`)}
                className="cyber-card flex items-center justify-between cursor-pointer"
              >
                <div>
                  <h3 className="text-white font-medium">{eng.project_name}</h3>
                  <p className="text-sm text-gray-400">
                    {eng.engagement_number} • {eng.organization_name}
                  </p>
                </div>
                <div className="flex items-center gap-6">
                  {/* Removed invalid `size` prop */}
                  <ProgressBar value={eng.progress_percentage} label="Progress" />
                  {eng.risk_level && (
                    <RiskBadge level={toRiskLevel(eng.risk_level)} />
                  )}
                  <span className="text-sm text-gray-500">
                    {new Date(eng.created_at).toLocaleDateString()}
                  </span>
                </div>
              </motion.div>
            ))
          ) : (
            <div className="cyber-card text-center py-16">
              <span className="text-5xl block mb-4">🛡️</span>
              <p className="text-gray-400 text-lg">No assessments yet</p>
              <p className="text-gray-500 text-sm mt-1">Start your first security assessment!</p>
              <button onClick={() => navigate("/chat")} className="btn-glow mt-4">
                Start Assessment
              </button>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
