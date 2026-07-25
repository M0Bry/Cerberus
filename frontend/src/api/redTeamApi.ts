/**
 * Red Team API — Attack plan, vuln scan, exploitation, evidence.
 */
import axiosInstance from "./axiosInstance";

export const redTeamApi = {
  getAttackPlan: (engagementId: string) => axiosInstance.get(`/red-team/${engagementId}/plan`),
  startScan: (engagementId: string) => axiosInstance.post(`/red-team/${engagementId}/scan`),
  getVulnerabilities: (engagementId: string) => axiosInstance.get(`/red-team/${engagementId}/vulnerabilities`),
  getExploitAttempts: (engagementId: string) => axiosInstance.get(`/red-team/${engagementId}/exploits`),
  getEvidence: (engagementId: string) => axiosInstance.get(`/red-team/${engagementId}/evidence`),
  getStatus: (engagementId: string) => axiosInstance.get(`/red-team/${engagementId}/status`),
  rollback: (engagementId: string) => axiosInstance.post(`/red-team/${engagementId}/rollback`),
};
