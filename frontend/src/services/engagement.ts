/**
 * Engagement Service — API calls for engagement management.
 */

import apiClient from "./api";

export const engagementService = {
  list: (params?: { page?: number; page_size?: number; status?: string; search?: string }) =>
    apiClient.get("/engagements", { params }),

  get: (id: string) => apiClient.get(`/engagements/${id}`),

  getSummary: (id: string) => apiClient.get(`/engagements/${id}/summary`),

  // AI Conversation
  sendMessage: (engagementId: string, message: string) =>
    apiClient.post(`/ai/${engagementId}/message`, { message }),

  getHistory: (engagementId: string) =>
    apiClient.get(`/ai/${engagementId}/history`),

  getSummaryAI: (engagementId: string) =>
    apiClient.get(`/ai/${engagementId}/summary`),

  confirmSummary: (engagementId: string) =>
    apiClient.post(`/ai/${engagementId}/confirm-summary`),

  // Scope
  getScope: (engagementId: string) =>
    apiClient.get(`/scope/${engagementId}`),

  approveScope: (engagementId: string) =>
    apiClient.post(`/scope/${engagementId}/approve`),

  // Rules of Engagement
  getRules: (engagementId: string) =>
    apiClient.get(`/rules/${engagementId}`),

  generateRules: (engagementId: string) =>
    apiClient.post(`/rules/${engagementId}/generate`),

  signRules: (engagementId: string, signedName: string) =>
    apiClient.post(`/rules/${engagementId}/sign`, { signed_name: signedName }),

  // Documents
  uploadDocument: (engagementId: string, file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return apiClient.post(`/documents/${engagementId}/upload`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },

  listDocuments: (engagementId: string) =>
    apiClient.get(`/documents/${engagementId}`),

  // OSINT
  startOSINT: (engagementId: string) =>
    apiClient.post(`/osint/${engagementId}/start`),

  getOSINTFindings: (engagementId: string, params?: { category?: string; page?: number }) =>
    apiClient.get(`/osint/${engagementId}/findings`, { params }),

  getKnowledgeGraph: (engagementId: string) =>
    apiClient.get(`/osint/${engagementId}/knowledge-graph`),

  // Attack Planning
  startAttackPlanning: (engagementId: string) =>
    apiClient.post(`/attack-planning/${engagementId}/analyze`),

  getAttackPaths: (engagementId: string) =>
    apiClient.get(`/attack-planning/${engagementId}/paths`),

  approveAttackPlan: (engagementId: string) =>
    apiClient.post(`/attack-planning/${engagementId}/approve`),

  // Red Team
  startRedTeam: (engagementId: string) =>
    apiClient.post(`/red-team/${engagementId}/start`),

  getRedTeamStatus: (engagementId: string) =>
    apiClient.get(`/red-team/${engagementId}/status`),

  getRedTeamFindings: (engagementId: string) =>
    apiClient.get(`/red-team/${engagementId}/findings`),

  // Risk Assessment
  startRiskAssessment: (engagementId: string) =>
    apiClient.post(`/risk-assessment/${engagementId}/start`),

  getRiskSummary: (engagementId: string) =>
    apiClient.get(`/risk-assessment/${engagementId}/summary`),

  // Reports
  generateReport: (engagementId: string) =>
    apiClient.post(`/reports/${engagementId}/generate`),

  listReports: (engagementId: string) =>
    apiClient.get(`/reports/${engagementId}`),

  downloadReport: (engagementId: string, reportId: string) =>
    apiClient.get(`/reports/${engagementId}/${reportId}/download`, {
      responseType: "blob",
    }),
};
