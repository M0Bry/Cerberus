/**
 * useMonitoring — Real-time monitoring + alerts + incidents.
 */
import { useQuery } from "@tanstack/react-query";
import { monitoringApi } from "../api/monitoringApi";

export function useMonitoring() {
  const dashboard = useQuery({
    queryKey: ["monitoringDashboard"],
    queryFn: () => monitoringApi.getDashboard().then((r) => r.data),
    refetchInterval: 10000,
  });
  const alerts = useQuery({
    queryKey: ["monitoringAlerts"],
    queryFn: () => monitoringApi.getAlerts().then((r) => r.data),
    refetchInterval: 5000,
  });
  const blockedIPs = useQuery({
    queryKey: ["blockedIPs"],
    queryFn: () => monitoringApi.getBlockedIPs().then((r) => r.data),
  });
  return { dashboard, alerts, blockedIPs };
}
