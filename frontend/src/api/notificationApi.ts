/**
 * Notification API — Notifications (list, mark read, preferences).
 */
import axiosInstance from "./axiosInstance";

export const notificationApi = {
  list: (params?: any) => axiosInstance.get("/notifications", { params }),
  markRead: (id: string) => axiosInstance.put(`/notifications/${id}/read`),
  markAllRead: () => axiosInstance.put("/notifications/read-all"),
  getPreferences: () => axiosInstance.get("/notifications/preferences"),
  updatePreferences: (data: any) => axiosInstance.put("/notifications/preferences", data),
};
