/** Notification Types */
export interface Notification {
  id: string;
  type: "system" | "alert" | "report_ready" | "scope_confirmed" | "engagement_update" | "security_alert";
  title: string;
  message: string;
  is_read: boolean;
  action_url?: string;
  metadata?: Record<string, any>;
  created_at: string;
  read_at?: string;
}

export interface NotificationPreference {
  email_enabled: boolean;
  push_enabled: boolean;
  sms_enabled: boolean;
  alert_severity_min: "critical" | "high" | "medium" | "low";
  digest_frequency: "realtime" | "hourly" | "daily" | "weekly";
}
