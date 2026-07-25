/**
 * Toast — Toast notification provider matching the reference design.
 */
import { useState, useCallback, createContext, useContext, ReactNode } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

type ToastType = "success" | "error" | "warning" | "info";

interface Toast {
  id: string;
  type: ToastType;
  message: string;
}

interface ToastContextValue {
  toast: (type: ToastType, message: string) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

const bgColors: Record<ToastType, string> = {
  success: "rgba(52,224,161,0.15)",
  error: "rgba(244,83,107,0.15)",
  warning: "rgba(224,185,58,0.15)",
  info: "rgba(47,125,250,0.15)",
};

const borderColors: Record<ToastType, string> = {
  success: "rgba(52,224,161,0.4)",
  error: "rgba(244,83,107,0.4)",
  warning: "rgba(224,185,58,0.4)",
  info: "rgba(47,125,250,0.4)",
};

const textColors: Record<ToastType, string> = {
  success: "#34e0a1",
  error: "#f4536b",
  warning: "#e0b93a",
  info: "#2f7dfa",
};

const icons: Record<ToastType, string> = {
  success: "✓",
  error: "✕",
  warning: "⚠",
  info: "ℹ",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((type: ToastType, message: string) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div
        style={{
          position: "fixed",
          top: 16,
          right: 16,
          zIndex: 9999,
          display: "flex",
          flexDirection: "column",
          gap: 8,
          maxWidth: 360,
        }}
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className="fade-up"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "12px 16px",
              borderRadius: 10,
              background: bgColors[t.type],
              border: `1px solid ${borderColors[t.type]}`,
              backdropFilter: "blur(8px)",
              fontFamily: MONO,
              fontSize: 12.5,
            }}
          >
            <span style={{ color: textColors[t.type], fontWeight: 700 }}>{icons[t.type]}</span>
            <span style={{ color: "#e8edf7", flex: 1 }}>{t.message}</span>
            <span
              onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
              style={{ color: "#5b6a86", cursor: "pointer", fontSize: 16 }}
            >
              ×
            </span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
