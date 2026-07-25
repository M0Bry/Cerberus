/** Report Types */
export interface Report {
  id: string;
  engagement_id: string;
  title: string;
  report_type: "executive" | "technical" | "full" | "compliance";
  status: "draft" | "generated" | "finalized" | "delivered";
  overall_security_score: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  generated_at: string;
}

export interface ReportSection {
  id: string;
  section_type: string;
  content: string;
  order_index: number;
}
