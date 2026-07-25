/**
 * useReports — Report generation + download + list.
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { reportApi } from "../api/reportApi";

export function useReports(engagementId: string) {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["reports", engagementId],
    queryFn: () => reportApi.list(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const generateMutation = useMutation({
    mutationFn: () => reportApi.generate(engagementId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", engagementId] }),
  });
  return { list, generate: generateMutation };
}
