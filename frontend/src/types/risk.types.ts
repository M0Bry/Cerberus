/** Risk Types */
export interface RiskFinding {
  id: string;
  title: string;
  description: string;
  likelihood: number; // 1-5
  impact: number; // 1-5
  risk_score: number;
  business_impact: string;
  recommendation: string;
  remediation_effort: "low" | "medium" | "high";
  remediation_timeline: string;
  compliance_refs: string[];
}

export interface RiskMatrix {
  cells: Array<{ likelihood: number; impact: number; count: number; level: string }>;
  total_findings: number;
}

export interface RemediationItem {
  id: string;
  finding_id: string;
  action_item: string;
  priority: "p1" | "p2" | "p3" | "p4";
  owner?: string;
  due_date?: string;
  status: "open" | "in_progress" | "completed" | "deferred";
}
