/**
 * Chat API — AI conversation with the Cerberus agent.
 *
 * Contract (backend/app/api/v1/endpoints/ai_conversation.py, mounted at /ai):
 *   POST /ai/:engagementId/message     {message, context?} → {success, message_id, ai_response, follow_up_questions?, context_updated}
 *   GET  /ai/:engagementId/history     → {success, engagement_id, messages: [{role, content, timestamp?}]}
 *   GET  /ai/:engagementId/summary     → structured engagement summary
 *   POST /ai/:engagementId/confirm-summary
 */
import axiosInstance from "./axiosInstance";

export interface ChatMessageItem {
  role: "user" | "assistant";
  content: string;
  timestamp?: string;
}

export interface SendMessageResponse {
  success: boolean;
  message_id: string;
  ai_response: string;
  follow_up_questions?: string[];
  context_updated?: boolean;
  /** "document" when the conversation is complete and the Scope of
   *  Engagement + Rules of Engagement document is ready for signature. */
  next_stage?: string | null;
}

export const chatApi = {
  sendMessage: (engagementId: string, data: { message: string; context?: Record<string, unknown> }) =>
    axiosInstance.post<SendMessageResponse>(`/ai/${engagementId}/message`, data),
  getHistory: (engagementId: string) =>
    axiosInstance.get<{ success: boolean; engagement_id: string; messages: ChatMessageItem[] }>(
      `/ai/${engagementId}/history`
    ),
  getSummary: (engagementId: string) =>
    axiosInstance.get(`/ai/${engagementId}/summary`),
  confirmSummary: (engagementId: string) =>
    axiosInstance.post(`/ai/${engagementId}/confirm-summary`),
};
