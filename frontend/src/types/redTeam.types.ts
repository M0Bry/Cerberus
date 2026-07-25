/** Red Team Types */
export interface AttackPlan {
  id: string;
  name: string;
  description: string;
  status: "planning" | "approved" | "executing" | "completed" | "failed";
  attack_paths: AttackPath[];
}

export interface AttackPath {
  id: string;
  name: string;
  entry_point: string;
  steps: AttackStep[];
  confidence_score: number;
  business_impact: number;
}

export interface AttackStep {
  step_number: number;
  action: string;
  tool?: string;
  result?: string;
  success?: boolean;
}

export interface ExploitAttempt {
  id: string;
  vulnerability_id: string;
  status: "attempted" | "successful" | "failed" | "blocked";
  poc_data: Record<string, any>;
  evidence_paths: string[];
  controlled: boolean;
  destructive: boolean;
}

export interface Evidence {
  id: string;
  type: "screenshot" | "video" | "log" | "network_capture" | "file";
  file_path: string;
  description: string;
  captured_at: string;
}
