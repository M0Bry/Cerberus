/**
 * Notifications Page — ported from the new front-end's notifications.html,
 * rewired from localStorage to the real endpoints:
 *
 *   GET  /notifications            → {total, unread_count, items[]}
 *   PUT  /notifications/:id/read
 *   PUT  /notifications/read-all
 *
 * Item: {id, notification_type, title, message, action_url, is_read, created_at}
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import UserChip from "../components/layout/UserChip";
import { notificationApi } from "../api/notificationApi";
import { formatDateTime } from "../utils/formatters";

interface NotifItem {
  id: string;
  notification_type: string;
  title: string;
  message: string;
  action_url?: string | null;
  is_read: boolean;
  created_at: string;
}

function iconFor(type: string): string {
  const t = (type || "").toLowerCase();
  if (t.includes("complete") || t.includes("success")) return "fa-circle-check";
  if (t.includes("progress") || t.includes("running")) return "fa-spinner";
  if (t.includes("fail") || t.includes("error")) return "fa-triangle-exclamation";
  if (t.includes("report")) return "fa-file-shield";
  if (t.includes("reply") || t.includes("message")) return "fa-reply";
  return "fa-bell";
}

export default function NotificationsPage() {
  const queryClient = useQueryClient();

  const listQuery = useQuery({
    queryKey: ["notifications"],
    queryFn: async () =>
      (await notificationApi.list()).data as {
        total: number;
        unread_count: number;
        items: NotifItem[];
      },
    refetchInterval: 60_000,
  });

  const items: NotifItem[] = listQuery.data?.items ?? [];
  const unread = listQuery.data?.unread_count ?? 0;

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });

  const markRead = useMutation({
    mutationFn: (id: string) => notificationApi.markRead(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: ["notifications"] });
      queryClient.setQueryData<{ items: NotifItem[] }>(["notifications"], (old) =>
        old ? { ...old, items: old.items.map((n) => (n.id === id ? { ...n, is_read: true } : n)) } : old
      );
      return { id };
    },
    onError: (_e, _id, ctx) => {
      queryClient.setQueryData<{ items: NotifItem[] }>(["notifications"], (old) =>
        old ? { ...old, items: old.items.map((n) => (n.id === ctx?.id ? { ...n, is_read: false } : n)) } : old
      );
    },
    onSettled: invalidate,
  });

  const markAll = useMutation({
    mutationFn: () => notificationApi.markAllRead(),
    onSuccess: invalidate,
  });

  return (
    <main className="main">
      <div className="topbar">
        <div className="crumb">
          <small>Activity{unread > 0 ? ` · ${unread} unread` : ""}</small>
          <h1>Notifications</h1>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {unread > 0 && (
            <button type="button" className="lnk" onClick={() => markAll.mutate()} disabled={markAll.isPending}>
              <i className="fas fa-check-double" /> Mark all read
            </button>
          )}
          <UserChip />
        </div>
      </div>

      <div className="panel">
        {items.length === 0 && (
          <div className="empty-state">
            <div className="empty-ico">
              <i className="fas fa-bell" />
            </div>
            <h3>All caught up</h3>
            <p>Updates about your assessments appear here, including progress made while you were offline.</p>
          </div>
        )}

        {items.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {items.map((n) => (
              <div
                key={n.id}
                className="notice"
                style={{
                  cursor: n.is_read ? "default" : "pointer",
                  boxShadow: n.is_read ? "none" : "inset 2px 0 0 var(--accent)",
                  opacity: n.is_read ? 0.72 : 1,
                }}
                onClick={() => !n.is_read && markRead.mutate(n.id)}
                title={n.is_read ? undefined : "Mark as read"}
              >
                <div className="nico">
                  <i className={`fas ${iconFor(n.notification_type)}`} />
                </div>
                <div>
                  <h4>{n.title}</h4>
                  <p>{n.message}</p>
                </div>
                <span className="when">{formatDateTime(n.created_at)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
