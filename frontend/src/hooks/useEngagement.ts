/**
 * useEngagement Hook — Custom hooks for engagement data fetching.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { engagementService } from "../services/engagement";

export function useEngagement(engagementId: string) {
  return useQuery({
    queryKey: ["engagement", engagementId],
    queryFn: () => engagementService.get(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
}

export function useEngagementSummary(engagementId: string) {
  return useQuery({
    queryKey: ["engagement-summary", engagementId],
    queryFn: () =>
      engagementService.getSummary(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
}

export function useOSINTFindings(engagementId: string) {
  return useQuery({
    queryKey: ["osint-findings", engagementId],
    queryFn: () =>
      engagementService.getOSINTFindings(engagementId).then((r) => r.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });
}

export function useAttackPaths(engagementId: string) {
  return useQuery({
    queryKey: ["attack-paths", engagementId],
    queryFn: () =>
      engagementService.getAttackPaths(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
}

export function useRedTeamFindings(engagementId: string) {
  return useQuery({
    queryKey: ["red-team-findings", engagementId],
    queryFn: () =>
      engagementService.getRedTeamFindings(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
}

export function useRiskSummary(engagementId: string) {
  return useQuery({
    queryKey: ["risk-summary", engagementId],
    queryFn: () =>
      engagementService.getRiskSummary(engagementId).then((r) => r.data),
    enabled: !!engagementId,
  });
}
