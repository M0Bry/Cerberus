/**
 * Chat Store — AI conversation state management.
 */

import { create } from "zustand";
import type { ChatMessage } from "../types";

interface ChatState {
  messages: ChatMessage[];
  sessionId: string | null;
  isLoading: boolean;
  scopeConfirmed: boolean;
  currentPhase: string | null;

  addMessage: (msg: ChatMessage) => void;
  setMessages: (msgs: ChatMessage[]) => void;
  setSessionId: (id: string) => void;
  setLoading: (loading: boolean) => void;
  setScopeConfirmed: (confirmed: boolean) => void;
  setCurrentPhase: (phase: string | null) => void;
  clearChat: () => void;
}

export const useChatStore = create<ChatState>((set) => ({
  messages: [],
  sessionId: null,
  isLoading: false,
  scopeConfirmed: false,
  currentPhase: null,

  addMessage: (msg) => set((s) => ({ messages: [...s.messages, msg] })),
  setMessages: (messages) => set({ messages }),
  setSessionId: (sessionId) => set({ sessionId }),
  setLoading: (isLoading) => set({ isLoading }),
  setScopeConfirmed: (scopeConfirmed) => set({ scopeConfirmed }),
  setCurrentPhase: (currentPhase) => set({ currentPhase }),
  clearChat: () => set({ messages: [], sessionId: null, scopeConfirmed: false, currentPhase: null }),
}));
