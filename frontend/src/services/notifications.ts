/**
 * Notifications Service — API calls for user notifications.
 */

import apiClient from "./api";

export const notificationService = {
  list: (params?: { unread_only?: boolean; page?: number; page_size?: number }) =>
    apiClient.get("/notifications", { params }),

  markAsRead: (notificationId: string) =>
    apiClient.put(`/notifications/${notificationId}/read`),

  markAllAsRead: () => apiClient.put("/notifications/read-all"),
};
