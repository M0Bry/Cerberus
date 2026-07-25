/**
 * Report API — Reports (generate, list, download PDF, preview).
 */
import axiosInstance from "./axiosInstance";

export const reportApi = {
  generate: (engagementId: string) => axiosInstance.post(`/reports/${engagementId}/generate`),
  list: (engagementId: string) => axiosInstance.get(`/reports/${engagementId}`),
  get: (reportId: string) => axiosInstance.get(`/reports/detail/${reportId}`),
  downloadPdf: (reportId: string) => axiosInstance.get(`/reports/${reportId}/download`, { responseType: "blob" }),
  preview: (reportId: string) => axiosInstance.get(`/reports/${reportId}/preview`),
  delete: (reportId: string) => axiosInstance.delete(`/reports/${reportId}`),
};
