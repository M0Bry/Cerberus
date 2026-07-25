/** Risk Store — Risk assessment state management. */
import { create } from "zustand";
interface RiskState {
  findings: any[]; matrix: any | null; scores: any | null;
  setFindings: (f: any[]) => void; setMatrix: (m: any) => void; setScores: (s: any) => void;
}
export const useRiskStore = create<RiskState>((set) => ({
  findings: [], matrix: null, scores: null,
  setFindings: (findings) => set({ findings }),
  setMatrix: (matrix) => set({ matrix }),
  setScores: (scores) => set({ scores }),
}));
