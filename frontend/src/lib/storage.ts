/**
 * Storage — Safe localStorage wrapper.
 */
export const storage = {
  get: (key: string): string | null => {
    try { return localStorage.getItem(key); } catch { return null; }
  },
  set: (key: string, value: string): void => {
    try { localStorage.setItem(key, value); } catch {}
  },
  remove: (key: string): void => {
    try { localStorage.removeItem(key); } catch {}
  },
  clear: (): void => {
    try { localStorage.clear(); } catch {}
  },
};
