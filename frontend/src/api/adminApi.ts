/**
 * Admin API — Users, engagements, system health.
 */
import axiosInstance from "./axiosInstance";

export const adminApi = {
  getUsers: (params?: any) => axiosInstance.get("/admin/users", { params }),
  getUser: (userId: string) => axiosInstance.get(`/admin/users/${userId}`),
  updateUser: (userId: string, data: any) => axiosInstance.put(`/admin/users/${userId}`, data),
  banUser: (userId: string) => axiosInstance.post(`/admin/users/${userId}/ban`),
  getEngagements: (params?: any) => axiosInstance.get("/admin/engagements", { params }),
  getSystemHealth: () => axiosInstance.get("/admin/system/health"),
  getAuditLogs: (params?: any) => axiosInstance.get("/admin/audit-logs", { params }),
};
