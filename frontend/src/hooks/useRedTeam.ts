/**
 * useRedTeam — Red Team operations + findings.
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { redTeamApi } from "../api/redTeamApi";

export function useRedTeam(engagementId: string) {
  const qc = useQueryClient();
  const plan = useQuery({
    queryKey: ["redTeamPlan", engagementId],
    queryFn: () => redTeamApi.getAttackPlan(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const vulns = useQuery({
    queryKey: ["redTeamVulns", engagementId],
    queryFn: () => redTeamApi.getVulnerabilities(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  const evidence = useQuery({
    queryKey: ["redTeamEvidence", engagementId],
    queryFn: () => redTeamApi.getEvidence(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
  return { plan, vulns, evidence };
}
