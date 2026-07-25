/** Admin Types */
export interface AdminUser {
  id: string;
  full_name: string;
  email: string;
  company_name: string;
  role: string;
  status: string;
  created_at: string;
  last_login_at?: string;
}

export interface AuditLogEntry {
  id: string;
  action: string;
  user_id?: string;
  resource_type?: string;
  resource_id?: string;
  ip_address?: string;
  details?: Record<string, any>;
  risk_flag: boolean;
  created_at: string;
}

export interface SystemMetric {
  metric_name: string;
  value: number;
  unit: string;
  recorded_at: string;
}
