/**
 * Admin Page — Uses adminStore for state + TanStack Query for server data.
 */
import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import DashboardLayout from "../components/layout/DashboardLayout";
import { adminApi } from "../api/adminApi";
import { useAdminStore } from "../stores/adminStore";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */
interface AdminDashboard {
  total_users: number;
  active_engagements: number;
  total_reports: number;
  system_health: string;
}

interface AdminUser {
  id: string;
  full_name: string;
  email: string;
  role: string;
  status: string;
  last_login_at: string | null;
}

interface PaginatedResponse<T> {
  items: T[];
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */
export default function AdminPage() {
  const { users, setUsers, setAuditLogs } = useAdminStore();

  /* ---- data fetching --------------------------------------------- */
  const { data: dashboard } = useQuery<AdminDashboard>({
    queryKey: ["adminDashboard"],
    queryFn: () => adminApi.getSystemHealth().then((r) => r.data),
  });

  const { data: usersData } = useQuery<PaginatedResponse<AdminUser>>({
    queryKey: ["adminUsers"],
    queryFn: () => adminApi.getUsers().then((r) => r.data),
  });

  const { data: logsData } = useQuery<PaginatedResponse<unknown>>({
    queryKey: ["adminAuditLogs"],
    queryFn: () => adminApi.getAuditLogs().then((r) => r.data),
  });

  /* ---- sync store ------------------------------------------------- */
  useEffect(() => {
    if (usersData?.items) setUsers(usersData.items);
    if (logsData?.items) setAuditLogs(logsData.items);
  }, [usersData, logsData, setUsers, setAuditLogs]);

  /* ---- render ----------------------------------------------------- */
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-white">Admin Dashboard</h1>

        {/* summary cards */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Total Users", value: dashboard?.total_users ?? users.length, icon: "👥" },
            { label: "Active Engagements", value: dashboard?.active_engagements ?? 0, icon: "📋" },
            { label: "Reports Generated", value: dashboard?.total_reports ?? 0, icon: "📄" },
            { label: "System Health", value: dashboard?.system_health ?? "Unknown", icon: "💚" },
          ].map((stat) => (
            <div key={stat.label} className="cyber-card text-center">
              <span className="text-2xl">{stat.icon}</span>
              <p className="text-2xl font-bold text-cerberus-blue mt-2">
                {stat.value}
              </p>
              <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
            </div>
          ))}
        </div>

        {/* user table */}
        <div className="cyber-card">
          <h2 className="text-lg font-semibold text-white mb-4">User Management</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cerberus-gray-700">
                  <th className="p-3 text-xs text-gray-400">Name</th>
                  <th className="p-3 text-xs text-gray-400">Email</th>
                  <th className="p-3 text-xs text-gray-400">Role</th>
                  <th className="p-3 text-xs text-gray-400">Status</th>
                  <th className="p-3 text-xs text-gray-400">Last Login</th>
                </tr>
              </thead>
              <tbody>
                {users.length > 0 ? (
                  users.map((u) => (
                    <tr key={u.id} className="border-b border-cerberus-gray-700/50">
                      <td className="p-3 text-sm text-white">{u.full_name}</td>
                      <td className="p-3 text-sm text-gray-400">{u.email}</td>
                      <td className="p-3 text-sm">
                        <span className="px-2 py-0.5 text-xs bg-cerberus-blue/20 text-cerberus-blue rounded-full">
                          {u.role}
                        </span>
                      </td>
                      <td className="p-3 text-sm">
                        <span
                          className={`px-2 py-0.5 text-xs rounded-full ${
                            u.status === "verified"
                              ? "bg-green-500/20 text-green-400"
                              : "bg-yellow-500/20 text-yellow-400"
                          }`}
                        >
                          {u.status}
                        </span>
                      </td>
                      <td className="p-3 text-sm text-gray-500">
                        {u.last_login_at
                          ? new Date(u.last_login_at).toLocaleDateString()
                          : "Never"}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-gray-500">
                      No users registered yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
