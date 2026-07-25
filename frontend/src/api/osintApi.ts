/**
 * OSINT API — Tasks (start, status, results, export) with full framework integration.
 */
import axiosInstance from "./axiosInstance";

export const osintApi = {
  // ─── Core Operations ─────────────────────────────────────
  startOSINT: (engagementId: string, modules?: string[]) =>
    axiosInstance.post(`/osint/${engagementId}/start`, { modules }),

  getStatus: (engagementId: string) =>
    axiosInstance.get(`/osint/${engagementId}/status`),

  getResults: (engagementId: string) =>
    axiosInstance.get(`/osint/${engagementId}/results`),

  // ─── Findings ────────────────────────────────────────────
  getFindings: (engagementId: string, params?: { category?: string; page?: number; page_size?: number }) =>
    axiosInstance.get(`/osint/${engagementId}/findings`, { params }),

  getFinding: (engagementId: string, findingId: string) =>
    axiosInstance.get(`/osint/${engagementId}/findings/${findingId}`),

  // ─── Knowledge Graph ─────────────────────────────────────
  getKnowledgeGraph: (engagementId: string) =>
    axiosInstance.get(`/osint/${engagementId}/knowledge-graph`),

  // ─── Summary ─────────────────────────────────────────────
  getSummary: (engagementId: string) =>
    axiosInstance.get(`/osint/${engagementId}/summary`),

  // ─── Export ──────────────────────────────────────────────
  exportResults: (engagementId: string, format: "json" | "csv" = "json") =>
    axiosInstance.get(`/osint/${engagementId}/export?format=${format}`, {
      responseType: "blob",
    }),

  // ─── Individual Module Tasks ─────────────────────────────
  startDNSScan: (engagementId: string, domain: string) =>
    axiosInstance.post(`/osint/${engagementId}/dns`, { domain }),

  startCTScan: (engagementId: string, domain: string) =>
    axiosInstance.post(`/osint/${engagementId}/ct`, { domain }),

  startGitHubScan: (engagementId: string, target: string) =>
    axiosInstance.post(`/osint/${engagementId}/github`, { target }),

  startSocialScan: (engagementId: string, target: string) =>
    axiosInstance.post(`/osint/${engagementId}/social`, { target }),

  startUsernameEnum: (engagementId: string, username: string) =>
    axiosInstance.post(`/osint/${engagementId}/username`, { username }),
};
