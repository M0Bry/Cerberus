/**
 * useAdmin — Admin dashboard data (users, engagements).
 */
import { useQuery } from "@tanstack/react-query";
import { adminApi } from "../api/adminApi";

export function useAdmin() {
  const users = useQuery({ queryKey: ["adminUsers"], queryFn: () => adminApi.getUsers().then((r) => r.data) });
  const health = useQuery({ queryKey: ["adminHealth"], queryFn: () => adminApi.getSystemHealth().then((r) => r.data) });
  const auditLogs = useQuery({ queryKey: ["adminAuditLogs"], queryFn: () => adminApi.getAuditLogs().then((r) => r.data) });
  return { users, health, auditLogs };
}
