/**
 * Modal — Dialog matching the exact reference design.
 */
import { ReactNode, useEffect } from "react";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: ReactNode;
  width?: number;
}

export default function Modal({ isOpen, onClose, title, children, width = 480 }: ModalProps) {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
      const handler = (e: KeyboardEvent) => e.key === "Escape" && onClose();
      window.addEventListener("keydown", handler);
      return () => {
        document.body.style.overflow = "";
        window.removeEventListener("keydown", handler);
      };
    }
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(0,0,0,0.7)",
          backdropFilter: "blur(4px)",
        }}
        onClick={onClose}
      />
      <div
        className="fade-up"
        style={{
          position: "relative",
          width: "100%",
          maxWidth: width,
          background: "#0a101c",
          border: "1px solid #152238",
          borderRadius: 18,
          padding: "32px",
          boxShadow: "0 30px 80px -40px rgba(0,0,20,0.8)",
        }}
      >
        {title && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
            <h3 style={{ fontFamily: DISPLAY, fontSize: 18, fontWeight: 700, color: "#e8edf7", margin: 0 }}>
              {title}
            </h3>
            <span
              onClick={onClose}
              style={{ color: "#5b6a86", cursor: "pointer", fontSize: 20, lineHeight: 1 }}
            >
              ×
            </span>
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
