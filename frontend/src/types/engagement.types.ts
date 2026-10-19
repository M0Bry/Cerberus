/**
 * Engagement Types — Assessment lifecycle (new front-end data shapes).
 *
 * Matches backend/app/schemas/engagement.py (EngagementResponse).
 * The new front-end "Assessment" row maps onto an Engagement:
 *   target   = project_name
 *   client   = organization_name
 *   started  = started_at || created_at
 *   status   = status
 *   risk     = risk_level
 */

export type EngagementStatus =
  | "pending"
  | "scoping"
  | "in_progress"
  | "completed"
  | "failed"
  | "cancelled"
  | string;

export type RiskLevel = "low" | "medium" | "high" | "critical" | string;

export interface Engagement {
  id: string;
  engagement_number: string;
  project_name: string;
  organization_name: string;
  objective: string | null;
  status: EngagementStatus;
  progress_percentage: number;
  current_phase: string | null;
  risk_level: RiskLevel | null;
  overall_security_score: number | null;
  estimated_duration_days: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface EngagementSummary {
  engagement_id: string;
  status: string;
  progress_percentage: number;
  [key: string]: unknown;
}

export interface EngagementListResponse {
  success: boolean;
  total: number;
  page: number;
  page_size: number;
  items: Engagement[];
}

/** Landing page stats (GET /public/stats). */
export interface LandingStats {
  assessments: number;
  organizations: number;
  vulnerabilities: number;
  reports: number;
}

/** Contact form payload (POST /public/contact). */
export interface ContactPayload {
  name: string;
  company?: string;
  email: string;
  interest: string;
  message: string;
}

/** Report row (backend/app/schemas/report.py ReportResponse). */
export interface ReportRow {
  id: string;
  // NOTE: the backend ReportItem does NOT carry engagement_id or created_at —
  // the engagement comes from the list wrapper and the date is "generated_at".
  // Both are therefore optional and normalized in the Reports page.
  engagement_id?: string;
  title: string;
  status?: string;
  created_at?: string;
  generated_at?: string;
  [key: string]: unknown;
}

/** Admin — user management row (GET /admin/users). */
export interface AdminUserRow {
  id: string;
  full_name: string;
  email: string;
  company_name?: string;
  role: string;
  status: string;
  created_at: string;
  last_login_at?: string | null;
  /** "paid" | "trial" | "suspended" */
  access_state?: string;
  plan_name?: string | null;
  trial_days_left?: number;
  [key: string]: unknown;
}

/** Admin — audit log entry (GET /admin/audit-logs). */
export interface AdminAuditEntry {
  id: string;
  timestamp?: string;
  created_at?: string;
  actor?: string;
  user_id?: string;
  action?: string;
  severity?: string;
  description?: string;
  target?: string;
  result?: string;
  [key: string]: unknown;
}
