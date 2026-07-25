/**
 * Dashboard Service — API calls for dashboard data.
 */

import apiClient from "./api";

export const dashboardService = {
  getOverview: () => apiClient.get("/dashboard/overview"),
  getStats: () => apiClient.get("/dashboard/stats"),
};
