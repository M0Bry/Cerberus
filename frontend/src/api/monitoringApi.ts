/**
 * Monitoring API — Continuous monitoring (alerts, health, incidents).
 */
import axiosInstance from "./axiosInstance";

export const monitoringApi = {
  getDashboard: () => axiosInstance.get("/monitoring/dashboard"),
  getAlerts: (params?: any) => axiosInstance.get("/monitoring/alerts", { params }),
  getAlert: (alertId: string) => axiosInstance.get(`/monitoring/alerts/${alertId}`),
  resolveAlert: (alertId: string) => axiosInstance.post(`/monitoring/alerts/${alertId}/resolve`),
  getIncidents: () => axiosInstance.get("/monitoring/incidents"),
  getBlockedIPs: () => axiosInstance.get("/monitoring/blocked-ips"),
  getHealth: () => axiosInstance.get("/monitoring/health"),
};
