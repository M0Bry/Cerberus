/**
 * useRiskAssessment — Risk matrix + scores + remediation.
 */
import { useQuery } from "@tanstack/react-query";
import { riskApi } from "../api/riskApi";

export function useRiskAssessment(engagementId: string) {
  const assessment = useQuery({
    queryKey: ["riskAssessment", engagementId],
    queryFn: () => riskApi.getAssessment(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const matrix = useQuery({
    queryKey: ["riskMatrix", engagementId],
    queryFn: () => riskApi.getMatrix(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const remediation = useQuery({
    queryKey: ["riskRemediation", engagementId],
    queryFn: () => riskApi.getRemediation(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  return { assessment, matrix, remediation };
}
