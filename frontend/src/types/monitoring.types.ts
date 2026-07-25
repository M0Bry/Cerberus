/** Monitoring Types */
export interface SecurityAlert {
  id: string;
  alert_type: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  source_ip?: string;
  status: "open" | "investigating" | "mitigated" | "resolved" | "false_positive";
  auto_defense_actions?: string[];
  created_at: string;
}

export interface HealthStatus {
  service: string;
  status: "healthy" | "degraded" | "down";
  uptime_percentage: number;
  last_check: string;
}

export interface BlockedIP {
  id: string;
  ip_address: string;
  reason: string;
  blocked_by: "system" | "admin" | "auto_defense";
  expires_at?: string;
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: "detected" | "contained" | "eradicated" | "recovered" | "closed";
  timeline: Array<{ timestamp: string; event: string }>;
  created_at: string;
}
