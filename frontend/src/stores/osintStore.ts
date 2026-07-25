/**
 * OSINT Store — OSINT phase state management.
 *
 * Manages: tasks, results, progress, active task, knowledge graph.
 */

import { create } from "zustand";
import type { OSINTTask, OSINTFinding, KnowledgeGraph, OSINTSummary } from "../types/osint.types";

interface OSINTState {
  // Tasks
  tasks: OSINTTask[];
  activeTask: string | null;

  // Findings
  findings: OSINTFinding[];

  // Knowledge Graph
  knowledgeGraph: KnowledgeGraph | null;

  // Summary
  summary: OSINTSummary | null;

  // Progress
  progress: number;
  isRunning: boolean;

  // Actions
  setTasks: (tasks: OSINTTask[]) => void;
  addTask: (task: OSINTTask) => void;
  updateTask: (id: string, updates: Partial<OSINTTask>) => void;
  setActiveTask: (id: string | null) => void;
  setFindings: (findings: OSINTFinding[]) => void;
  addFinding: (finding: OSINTFinding) => void;
  setKnowledgeGraph: (graph: KnowledgeGraph | null) => void;
  setSummary: (summary: OSINTSummary | null) => void;
  setProgress: (progress: number) => void;
  setIsRunning: (running: boolean) => void;
  reset: () => void;
}

export const useOSINTStore = create<OSINTState>((set) => ({
  tasks: [],
  activeTask: null,
  findings: [],
  knowledgeGraph: null,
  summary: null,
  progress: 0,
  isRunning: false,

  setTasks: (tasks) => set({ tasks }),
  addTask: (task) => set((s) => ({ tasks: [...s.tasks, task] })),
  updateTask: (id, updates) =>
    set((s) => ({
      tasks: s.tasks.map((t) => (t.id === id ? { ...t, ...updates } : t)),
    })),
  setActiveTask: (activeTask) => set({ activeTask }),
  setFindings: (findings) => set({ findings }),
  addFinding: (finding) => set((s) => ({ findings: [...s.findings, finding] })),
  setKnowledgeGraph: (knowledgeGraph) => set({ knowledgeGraph }),
  setSummary: (summary) => set({ summary }),
  setProgress: (progress) => set({ progress }),
  setIsRunning: (isRunning) => set({ isRunning }),
  reset: () =>
    set({
      tasks: [],
      activeTask: null,
      findings: [],
      knowledgeGraph: null,
      summary: null,
      progress: 0,
      isRunning: false,
    }),
}));
