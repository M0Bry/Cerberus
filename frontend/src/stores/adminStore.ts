/** Admin Store — Admin dashboard state management. */
import { create } from "zustand";
interface AdminState {
  users: any[]; engagements: any[]; auditLogs: any[];
  setUsers: (u: any[]) => void; setEngagements: (e: any[]) => void; setAuditLogs: (l: any[]) => void;
}
export const useAdminStore = create<AdminState>((set) => ({
  users: [], engagements: [], auditLogs: [],
  setUsers: (users) => set({ users }),
  setEngagements: (engagements) => set({ engagements }),
  setAuditLogs: (auditLogs) => set({ auditLogs }),
}));
