/**
 * useScope — Scope document lifecycle (draft → confirm).
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { scopeApi } from "../api/scopeApi";

export function useScope(engagementId: string) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["scope", engagementId],
    queryFn: () => scopeApi.getScope(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const confirmMutation = useMutation({
    mutationFn: () => scopeApi.confirmScope(engagementId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scope", engagementId] }),
  });
  return { ...query, confirmScope: confirmMutation };
}
