/**
 * RedTeam Store — Red Team operations state.
 */

import { create } from "zustand";

interface Vuln {
  id: string;
  title: string;
  severity: string;
  status: string;
  affected_assets: string;
}

interface RedTeamState {
  operationId: string | null;
  status: string;
  findings: Vuln[];
  attackPaths: any[];
  currentPath: string | null;
  progress: number;

  setOperationId: (id: string | null) => void;
  setStatus: (status: string) => void;
  setFindings: (findings: Vuln[]) => void;
  setAttackPaths: (paths: any[]) => void;
  setCurrentPath: (path: string | null) => void;
  setProgress: (progress: number) => void;
}

export const useRedTeamStore = create<RedTeamState>((set) => ({
  operationId: null,
  status: "idle",
  findings: [],
  attackPaths: [],
  currentPath: null,
  progress: 0,

  setOperationId: (operationId) => set({ operationId }),
  setStatus: (status) => set({ status }),
  setFindings: (findings) => set({ findings }),
  setAttackPaths: (attackPaths) => set({ attackPaths }),
  setCurrentPath: (currentPath) => set({ currentPath }),
  setProgress: (progress) => set({ progress }),
}));
