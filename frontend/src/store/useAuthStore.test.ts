import { describe, it, expect, beforeEach, vi } from "vitest";
import { useAuthStore } from "./useAuthStore";

// Node test env has no localStorage — stub it before the store's DEV branch
// touches it.
const store = new Map<string, string>();
vi.stubGlobal(
  "localStorage",
  {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  }
);

describe("useAuthStore", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, isAuthenticated: false });
    store.clear();
  });

  it("starts unauthenticated", () => {
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("setTokens marks the session authenticated and stores dev tokens", () => {
    useAuthStore.getState().setTokens("access-1", "refresh-1");
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
    expect(store.get("access_token")).toBe("access-1");
    expect(store.get("refresh_token")).toBe("refresh-1");
  });

  it("setUser keeps the user", () => {
    useAuthStore.getState().setUser({ id: "u1", email: "x@y.z", full_name: "X" } as any);
    expect(useAuthStore.getState().user?.email).toBe("x@y.z");
  });

  it("logout clears user, flag and stored tokens", () => {
    useAuthStore.getState().setTokens("a", "r");
    useAuthStore.getState().setUser({ id: "u1", email: "x@y.z", full_name: "X" } as any);
    useAuthStore.getState().logout();
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().user).toBeNull();
    expect(store.has("access_token")).toBe(false);
    expect(store.has("refresh_token")).toBe(false);
  });
});
