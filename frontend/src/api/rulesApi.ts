/**
 * Rules of Engagement API — the Scope of Engagement + RoE legal document.
 *
 * Contract (backend/app/api/v1/endpoints/rules_of_engagement.py, mounted at /rules):
 *   GET  /rules/:engagementId            → {success, id, engagement_id, document_html,
 *                                          *_clause..., is_signed, created_at, signed_at?}
 *   POST /rules/:engagementId/generate   → same (auto-generates from the scope)
 *   POST /rules/:engagementId/sign       {signed_name} → {success, message, signature_id, signed_at, pdf_url?}
 *
 * The document is created by the backend automatically once the AI
 * conversation has gathered enough information (message response carries
 * next_stage: "document"). The client then reviews it and signs by typing
 * their full legal name (paste disabled in the UI — deliberate action).
 */
import axiosInstance from "./axiosInstance";

export interface RulesDocument {
  success: boolean;
  id: string;
  engagement_id: string;
  document_html: string;
  authorization_clause: string;
  methodology_clause: string;
  prohibited_actions_clause: string;
  client_obligations_clause: string;
  liability_clause: string;
  confidentiality_clause: string;
  is_signed: boolean;
  created_at: string;
  signed_at?: string | null;
}

export interface SignatureResponse {
  success: boolean;
  message: string;
  signature_id: string;
  signed_at: string;
  pdf_url?: string | null;
}

export const rulesApi = {
  get: (engagementId: string) =>
    axiosInstance.get<RulesDocument>(`/rules/${engagementId}`),
  generate: (engagementId: string) =>
    axiosInstance.post<RulesDocument>(`/rules/${engagementId}/generate`),
  sign: (engagementId: string, data: { signed_name: string }) =>
    axiosInstance.post<SignatureResponse>(`/rules/${engagementId}/sign`, data),
};
