/**
 * Scope API — Scope document CRUD, confirm, update, export.
 */
import axiosInstance from "./axiosInstance";

export const scopeApi = {
  getScope: (engagementId: string) => axiosInstance.get(`/scope/${engagementId}`),
  createScope: (engagementId: string, data: any) => axiosInstance.post(`/scope/${engagementId}`, data),
  updateScope: (engagementId: string, data: any) => axiosInstance.put(`/scope/${engagementId}`, data),
  confirmScope: (engagementId: string) => axiosInstance.post(`/scope/${engagementId}/confirm`),
  exportScope: (engagementId: string) => axiosInstance.get(`/scope/${engagementId}/export`, { responseType: "blob" }),
};
