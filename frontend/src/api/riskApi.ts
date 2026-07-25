/**
 * Risk API — Risk assessment (matrix, scores, recommendations).
 */
import axiosInstance from "./axiosInstance";

export const riskApi = {
  getAssessment: (engagementId: string) => axiosInstance.get(`/risk/${engagementId}`),
  getMatrix: (engagementId: string) => axiosInstance.get(`/risk/${engagementId}/matrix`),
  getFindings: (engagementId: string) => axiosInstance.get(`/risk/${engagementId}/findings`),
  getRemediation: (engagementId: string) => axiosInstance.get(`/risk/${engagementId}/remediation`),
  getScores: (engagementId: string) => axiosInstance.get(`/risk/${engagementId}/scores`),
};
