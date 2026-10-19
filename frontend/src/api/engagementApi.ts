/**
 * Engagement API — Assessment/engagement lifecycle.
 *
 * Contract (backend/app/api/v1/endpoints/engagements.py):
 *   GET  /engagements/               → {success, total, page, page_size, items: Engagement[]}
 *   POST /engagements/               {project_name, organization_name, objective?, description?}
 *   GET  /engagements/:id            → Engagement
 *   GET  /engagements/:id/summary    → EngagementSummary
 */
import axiosInstance from "./axiosInstance";
import type { Engagement, EngagementSummary } from "../types";

export const engagementApi = {
  list: (params?: { page?: number; page_size?: number; status?: string }) =>
    axiosInstance.get<{ success: boolean; total: number; items: Engagement[] }>(
      "/engagements",
      { params }
    ),
  create: (data: {
    project_name: string;
    organization_name: string;
    objective?: string;
    description?: string;
  }) => axiosInstance.post<Engagement>("/engagements", data),
  get: (id: string) => axiosInstance.get<Engagement>(`/engagements/${id}`),
  summary: (id: string) =>
    axiosInstance.get<EngagementSummary>(`/engagements/${id}/summary`),
};
