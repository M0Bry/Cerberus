/** Scope Store — Scope document state management. */
import { create } from "zustand";
interface ScopeState {
  scope: any | null; confirmed: boolean; selectedPhases: string[];
  setScope: (scope: any) => void; setConfirmed: (v: boolean) => void; togglePhase: (phase: string) => void; reset: () => void;
}
export const useScopeStore = create<ScopeState>((set) => ({
  scope: null, confirmed: false, selectedPhases: ["osint", "red_team", "risk_assessment"],
  setScope: (scope) => set({ scope }),
  setConfirmed: (confirmed) => set({ confirmed }),
  togglePhase: (phase) => set((s) => ({ selectedPhases: s.selectedPhases.includes(phase) ? s.selectedPhases.filter((p) => p !== phase) : [...s.selectedPhases, phase] })),
  reset: () => set({ scope: null, confirmed: false, selectedPhases: ["osint", "red_team", "risk_assessment"] }),
}));
