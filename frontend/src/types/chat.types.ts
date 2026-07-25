/** Chat Types */
export interface ChatMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface ChatSession {
  id: string;
  engagement_id: string;
  status: "intake" | "scope_generation" | "scope_confirmed" | "in_progress" | "completed";
  summary_text?: string;
  scope_json?: Record<string, any>;
  created_at: string;
}

export interface ScopeSummary {
  organization_profile: string;
  business_objectives: string;
  critical_assets: string;
  authorized_targets: string;
  out_of_scope: string;
  expected_duration: string;
  security_priorities: string;
  technical_constraints: string;
  compliance_considerations: string;
  potential_risks: string;
}
