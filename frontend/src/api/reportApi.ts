/**
 * Report API — Reports (list per engagement, download PDF).
 *
 * Contract (backend/app/api/v1/endpoints/reports.py):
 *   POST /reports/:engagementId/generate
 *   GET  /reports/:engagementId                 → list of reports for the engagement
 *   GET  /reports/:engagementId/:reportId       → single report
 *   GET  /reports/:engagementId/:reportId/download → PDF bytes
 */
import axiosInstance from "./axiosInstance";
import type { ReportRow } from "../types";

export const reportApi = {
  generate: (engagementId: string) => axiosInstance.post(`/reports/${engagementId}/generate`),
  list: (engagementId: string) =>
    axiosInstance.get<{ success: boolean; items?: ReportRow[]; reports?: ReportRow[] }>(
      `/reports/${engagementId}`
    ),
  get: (engagementId: string, reportId: string) =>
    axiosInstance.get(`/reports/${engagementId}/${reportId}`),
  downloadPdf: (engagementId: string, reportId: string) =>
    axiosInstance.get(`/reports/${engagementId}/${reportId}/download`, {
      responseType: "blob",
    }),
};
