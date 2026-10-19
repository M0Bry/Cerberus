import { useQuery, useQueryClient } from "@tanstack/react-query";
import { paymentsApi, type AccessInfo } from "../api/paymentsApi";
import { useAuthStore } from "../store/useAuthStore";

/**
 * Access hook — the account's effective state: trial / paid / suspended.
 *
 * The 7-day free-trial rule: after the week expires without a subscription
 * the account is suspended in the database until payment. The UI uses this
 * to (a) show the trial countdown, (b) block new assessments when
 * suspended, and (c) show the plan on the sidebar.
 *
 * Refresh cadence: every 60s (trial countdown) + refetch on window focus.
 * Call `refreshAccess()` after events that change state (payment webhook
 * round-trip, plan activation) to avoid waiting for the next tick.
 */
export function useAccess(enabled: boolean = true) {
  const queryClient = useQueryClient();
  const query = useQuery<AccessInfo>({
    queryKey: ["me", "access"],
    queryFn: async () => (await paymentsApi.getAccess()).data,
    enabled,
    staleTime: 30_000,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
    retry: false,
  });

  const refreshAccess = () =>
    queryClient.invalidateQueries({ queryKey: ["me", "access"] });

  return { ...query, refreshAccess };
}

export function useIsAuthenticated(): boolean {
  return useAuthStore((s) => s.isAuthenticated);
}
