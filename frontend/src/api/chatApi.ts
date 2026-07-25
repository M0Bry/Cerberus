/**
 * Chat API — AI Chat (messages, SSE stream, history).
 */
import axiosInstance from "./axiosInstance";

export const chatApi = {
  sendMessage: (engagementId: string, data: { message: string }) =>
    axiosInstance.post(`/chat/${engagementId}/messages`, data),
  getHistory: (engagementId: string) =>
    axiosInstance.get(`/chat/${engagementId}/history`),
  getSessions: () => axiosInstance.get("/chat/sessions"),
  getSession: (sessionId: string) => axiosInstance.get(`/chat/sessions/${sessionId}`),
  // SSE stream URL helper
  getStreamUrl: (engagementId: string) =>
    `${import.meta.env.VITE_API_URL || "/api/v1"}/chat/${engagementId}/stream`,
};
