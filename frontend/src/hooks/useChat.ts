/**
 * useChat — AI chat (send, streaming, history, scope).
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { chatApi } from "../api/chatApi";

export function useChat(engagementId: string) {
  const qc = useQueryClient();
  const history = useQuery({
    queryKey: ["chatHistory", engagementId],
    queryFn: () => chatApi.getHistory(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const sendMutation = useMutation({
    mutationFn: (message: string) => chatApi.sendMessage(engagementId, { message }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["chatHistory", engagementId] }),
  });
  return { history, sendMessage: sendMutation };
}
