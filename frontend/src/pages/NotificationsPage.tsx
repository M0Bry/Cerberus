/**
 * Notifications Page — Uses useNotifications hook.
 */

import { useNotifications } from "../hooks/useNotifications";
import { useNotificationStore } from "../stores/notificationStore";
import { useEffect } from "react";
import DashboardLayout from "../components/layout/DashboardLayout";

export default function NotificationsPage() {
  const { list, markRead, markAllRead } = useNotifications();
  const { notifications, unreadCount, setNotifications, markRead: storeMarkRead, markAllRead: storeMarkAllRead } = useNotificationStore();

  useEffect(() => {
    if ((list.data as any)?.items) {
      setNotifications((list.data as any).items);
    }
  }, [list.data]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-white">Notifications</h1>
            {unreadCount > 0 && (
              <span className="px-2 py-0.5 text-xs bg-cerberus-blue/20 text-cerberus-blue border border-cerberus-blue/30 rounded-full">
                {unreadCount} unread
              </span>
            )}
          </div>
          <button
            onClick={() => { markAllRead.mutate(); storeMarkAllRead(); }}
            className="text-xs text-cerberus-blue hover:underline"
          >
            Mark all as read
          </button>
        </div>
        {list.isLoading ? (
          <div className="cyber-card text-center text-gray-400 py-12">Loading...</div>
        ) : notifications.length ? (
          <div className="space-y-2">
            {notifications.map((n: any) => (
              <div
                key={n.id}
                onClick={() => { if (!n.is_read) { markRead.mutate(n.id); storeMarkRead(n.id); } }}
                className={`cyber-card flex items-start gap-4 cursor-pointer ${!n.is_read ? "border-l-2 border-cerberus-blue" : ""}`}
              >
                <span className="text-lg">
                  {n.type === "alert" ? "⚠️" : n.type === "security" ? "🔒" : "ℹ️"}
                </span>
                <div className="flex-1">
                  <h3 className="text-sm text-white font-medium">{n.title}</h3>
                  <p className="text-xs text-gray-400 mt-1">{n.message}</p>
                </div>
                <span className="text-[10px] text-gray-600">
                  {new Date(n.created_at).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="cyber-card text-center py-16">
            <span className="text-4xl block mb-2">🔔</span>
            <p className="text-gray-500">No notifications yet.</p>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
