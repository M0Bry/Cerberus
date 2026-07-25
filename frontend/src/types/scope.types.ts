/** Scope Types */
export interface ScopeDoc { id: string; engagement_id: string; status: "draft" | "confirmed" | "active" | "completed"; in_scope_domains: string[]; in_scope_ips: string[]; in_scope_assets: string[]; out_of_scope_items: string[]; selected_phases: string[]; confirmed_at?: string; created_at: string; updated_at: string; }
export interface TargetAsset { type: "domain" | "ip" | "url" | "cloud_resource"; value: string; description?: string; }
