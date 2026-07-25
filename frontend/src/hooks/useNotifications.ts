/**
 * useNotifications — Notification center + unread count.
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { notificationApi } from "../api/notificationApi";

export function useNotifications() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["notifications"],
    queryFn: () => notificationApi.list().then((r) => r.data),
    refetchInterval: 30000,
  });
  const markReadMutation = useMutation({
    mutationFn: (id: string) => notificationApi.markRead(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const markAllReadMutation = useMutation({
    mutationFn: () => notificationApi.markAllRead(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notifications"] }),
  });
  return { list, markRead: markReadMutation, markAllRead: markAllReadMutation };
}
