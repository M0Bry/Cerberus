/**
 * UI Store — Global UI state (theme, sidebar, modal, toast queue).
 */

import { create } from "zustand";

interface UIState {
  theme: "dark" | "light" | "system";
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  modalOpen: boolean;
  modalContent: React.ReactNode | null;

  setTheme: (theme: "dark" | "light" | "system") => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  openModal: (content: React.ReactNode) => void;
  closeModal: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  theme: "dark",
  sidebarOpen: true,
  sidebarCollapsed: false,
  modalOpen: false,
  modalContent: null,

  setTheme: (theme) => set({ theme }),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
  openModal: (content) => set({ modalOpen: true, modalContent: content }),
  closeModal: () => set({ modalOpen: false, modalContent: null }),
}));
