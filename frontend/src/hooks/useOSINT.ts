/**
 * useOSINT — OSINT phase tracking + results with full framework integration.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { osintApi } from "../api/osintApi";

export function useOSINT(engagementId: string) {
  const qc = useQueryClient();

  // ─── Status (polls every 5 seconds) ─────────────────────
  const status = useQuery({
    queryKey: ["osintStatus", engagementId],
    queryFn: () => osintApi.getStatus(engagementId).then((r) => r.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // ─── Summary ─────────────────────────────────────────────
  const summary = useQuery({
    queryKey: ["osintSummary", engagementId],
    queryFn: () => osintApi.getSummary(engagementId).then((r) => r.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // ─── Findings ────────────────────────────────────────────
  const findings = useQuery({
    queryKey: ["osintFindings", engagementId],
    queryFn: () => osintApi.getFindings(engagementId, { page_size: 200 }).then((r) => r.data),
    enabled: !!engagementId,
    refetchInterval: 5000,
  });

  // ─── Knowledge Graph ─────────────────────────────────────
  const knowledgeGraph = useQuery({
    queryKey: ["osintKnowledgeGraph", engagementId],
    queryFn: () => osintApi.getKnowledgeGraph(engagementId).then((r) => r.data),
    enabled: !!engagementId,
    refetchInterval: 10000,
  });

  // ─── Start OSINT ─────────────────────────────────────────
  const startMutation = useMutation({
    mutationFn: (modules?: string[]) => osintApi.startOSINT(engagementId, modules),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["osintStatus", engagementId] });
      qc.invalidateQueries({ queryKey: ["osintSummary", engagementId] });
      qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] });
    },
  });

  // ─── Individual Module Mutations ─────────────────────────
  const dnsMutation = useMutation({
    mutationFn: (domain: string) => osintApi.startDNSScan(engagementId, domain),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] }),
  });

  const githubMutation = useMutation({
    mutationFn: (target: string) => osintApi.startGitHubScan(engagementId, target),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] }),
  });

  const socialMutation = useMutation({
    mutationFn: (target: string) => osintApi.startSocialScan(engagementId, target),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] }),
  });

  const usernameMutation = useMutation({
    mutationFn: (username: string) => osintApi.startUsernameEnum(engagementId, username),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["osintFindings", engagementId] }),
  });

  return {
    status,
    summary,
    findings,
    knowledgeGraph,
    startOSINT: startMutation,
    startDNS: dnsMutation,
    startGitHub: githubMutation,
    startSocial: socialMutation,
    startUsername: usernameMutation,
  };
}
