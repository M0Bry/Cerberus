/**
 * useSystemHealth — Health check + uptime + performance.
 */
import { useQuery } from "@tanstack/react-query";
import { healthApi } from "../api/healthApi";

export function useSystemHealth() {
  return useQuery({
    queryKey: ["systemHealth"],
    queryFn: () => healthApi.protectedHealth().then((r) => r.data),
    refetchInterval: 30000,
  });
}
