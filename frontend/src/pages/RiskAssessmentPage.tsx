/**
 * RiskAssessmentPage — Uses useRiskAssessment hook + riskStore.
 */

import { useEffect } from "react";
import { useParams } from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import RiskScoreCard from "../components/risk/RiskScoreCard";
import RiskMatrix from "../components/risk/RiskMatrix";
import { useRiskAssessment } from "../hooks/useRiskAssessment";
import { useRiskStore } from "../stores/riskStore"; // ❗ removed `type Finding` import

/* ------------------------------------------------------------------ */
/*  Local type for the findings rendered in this page                  */
/* ------------------------------------------------------------------ */

interface RiskFinding {
  id: string;
  title: string;
  description?: string;
  risk_level: string;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function RiskAssessmentPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const { assessment, matrix } = useRiskAssessment(engagementId || "");
  const { findings, setFindings, setMatrix } = useRiskStore();

  // Sync assessment data into the store
  useEffect(() => {
    if (assessment.data?.items) {
      // `as any[]` is used because riskStore may not export a `Finding` type
      setFindings(assessment.data.items as any[]);
    }
  }, [assessment.data, setFindings]);

  // Sync matrix data into the store
  useEffect(() => {
    if (matrix.data) {
      setMatrix(matrix.data as any);
    }
  }, [matrix.data, setMatrix]);

  // Derive display findings from store
  const displayFindings: RiskFinding[] = findings.map((f: any) => ({
    id: f.id,
    title: f.title || f.vulnerability_title || "",
    description: f.description,
    risk_level: f.risk_level || f.severity || "unknown",
  }));

  return (
    <DashboardLayout>
      <h1 className="text-3xl font-bold text-white mb-6">Risk Assessment</h1>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 🔧 Temporary `as any` — remove after fixing RiskScoreCard/RiskMatrix props */}
        <RiskScoreCard engagementId={engagementId as any} />
        <RiskMatrix engagementId={engagementId as any} />
      </div>
      {displayFindings.length > 0 && (
        <div className="mt-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Findings ({displayFindings.length})
          </h2>
          <div className="space-y-2">
            {displayFindings.map((f) => (
              <div key={f.id} className="cyber-card flex items-center justify-between">
                <div>
                  <p className="text-sm text-white font-medium">{f.title}</p>
                  <p className="text-xs text-gray-400">{f.description}</p>
                </div>
                <span
                  className={`px-2 py-0.5 text-xs rounded-full ${
                    f.risk_level === "critical"
                      ? "bg-red-500/20 text-red-400"
                      : f.risk_level === "high"
                        ? "bg-orange-500/20 text-orange-400"
                        : f.risk_level === "medium"
                          ? "bg-yellow-500/20 text-yellow-400"
                          : "bg-green-500/20 text-green-400"
                  }`}
                >
                  {f.risk_level.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
