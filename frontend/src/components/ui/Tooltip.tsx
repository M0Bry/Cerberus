/**
 * Tooltip — Tooltip matching the reference design.
 */
import { useState, ReactNode } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface TooltipProps {
  content: string;
  children: ReactNode;
  position?: "top" | "bottom";
}

export default function Tooltip({ content, children, position = "top" }: TooltipProps) {
  const [show, setShow] = useState(false);

  return (
    <div
      style={{ position: "relative", display: "inline-block" }}
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div
          style={{
            position: "absolute",
            zIndex: 50,
            padding: "6px 12px",
            fontSize: 11,
            color: "#e8edf7",
            background: "#0a101c",
            border: "1px solid #152238",
            borderRadius: 8,
            whiteSpace: "nowrap",
            fontFamily: MONO,
            ...(position === "top"
              ? { bottom: "100%", marginBottom: 8 }
              : { top: "100%", marginTop: 8 }),
            left: "50%",
            transform: "translateX(-50%)",
          }}
        >
          {content}
        </div>
      )}
    </div>
  );
}
