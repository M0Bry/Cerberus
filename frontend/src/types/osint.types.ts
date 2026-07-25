/**
 * OSINT Types — Complete type definitions for the OSINT framework.
 */

// ─── Task Types ────────────────────────────────────────────
export type OSINTTaskStatus = "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";
export type OSINTTaskType =
  | "domain_enum"
  | "email_harvest"
  | "social_recon"
  | "subdomain_enum"
  | "whois_lookup"
  | "dns_enum"
  | "public_records"
  | "asset_discovery"
  | "github_scan"
  | "username_enum"
  | "image_analysis";

export interface OSINTTask {
  id: string;
  engagement_id: string;
  task_type: OSINTTaskType;
  status: OSINTTaskStatus;
  config: Record<string, any>;
  result_data?: Record<string, any>;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

// ─── Result Types ──────────────────────────────────────────
export interface OSINTResult {
  domains: string[];
  emails: string[];
  subdomains: string[];
  technologies: string[];
  credentials: CredentialExposure[];
  social_profiles: SocialProfile[];
}

export interface CredentialExposure {
  email: string;
  source: string;
  breach_name?: string;
  breach_date?: string;
  data_types?: string[];
}

export interface SocialProfile {
  platform: string;
  url: string;
  username: string;
  exists: boolean;
  category: string;
  importance: "high" | "medium" | "low";
  response_time?: number;
}

// ─── Domain Types ──────────────────────────────────────────
export interface DomainInfo {
  domain: string;
  registrar?: string;
  creation_date?: string;
  expiry_date?: string;
  name_servers: string[];
  dns_records?: DNSRecord[];
  technologies?: string[];
  subdomains?: string[];
}

export interface DNSRecord {
  type: string;
  values: string[];
}

export interface SubdomainInfo {
  subdomain: string;
  ip?: string;
  status?: number;
  technology?: string;
  source: string;
}

// ─── Asset Types ───────────────────────────────────────────
export interface Asset {
  id: string;
  type: "domain" | "subdomain" | "email" | "ip" | "technology" | "username";
  value: string;
  source: string;
  confidence: number;
  risk_score: number;
  discovered_at: string;
}

// ─── Knowledge Graph Types ─────────────────────────────────
export interface KnowledgeGraphNode {
  id: string;
  node_type: string;
  label: string;
  properties?: Record<string, any>;
}

export interface KnowledgeGraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  weight: number;
  confidence?: number;
}

export interface KnowledgeGraph {
  nodes: KnowledgeGraphNode[];
  edges: KnowledgeGraphEdge[];
}

// ─── Finding Types ─────────────────────────────────────────
export type FindingCategory = "technical" | "credential" | "employee" | "technology" | "historical_web";

export interface OSINTFinding {
  id: string;
  category: FindingCategory;
  title: string;
  description: string;
  evidence?: string;
  source_url?: string;
  confidence_score: number;
  raw_data?: Record<string, any>;
  discovered_at: string;
}

// ─── Summary Types ─────────────────────────────────────────
export interface OSINTSummary {
  engagement_id: string;
  total_findings: number;
  domains_discovered: number;
  technologies_identified: number;
  employee_profiles: number;
  exposed_services: number;
  archived_resources: number;
  leaked_credentials: number;
  risk_distribution: Record<FindingCategory, number>;
}

// ─── GitHub Intelligence ───────────────────────────────────
export interface GitHubFinding {
  type: string;
  value_redacted: string;
  source_url: string;
  confidence: number;
  context?: string;
}

export interface GitHubRepo {
  name: string;
  description?: string;
  language?: string;
  stars: number;
  updated_at?: string;
}

// ─── Report Types ──────────────────────────────────────────
export interface OSINTReport {
  report_id: string;
  target: string;
  target_type: string;
  classification: string;
  executive_summary: string;
  risk_assessment: {
    overall_score: number;
    level: string;
    indicators: number;
  };
  confidence_level: number;
  recommendations: string[];
  sources: string[];
  timestamp: string;
}
