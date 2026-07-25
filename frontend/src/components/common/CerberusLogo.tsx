/**
 * Logo — Exact Cerberus logo from the reference design.
 */
import { Shield } from "lucide-react";

interface LogoProps {
  size?: "sm" | "md" | "lg";
  onClick?: () => void;
}

const sizeMap = { sm: 14, md: 18, lg: 24 };
const fontSizeMap = { sm: 12, md: 14, lg: 18 };

export default function CerberusLogo({ size = "md", onClick }: LogoProps) {
  return (
    <div
      onClick={onClick}
      style={{ display: "flex", alignItems: "center", gap: 8, cursor: onClick ? "pointer" : "default" }}
    >
      <Shield size={sizeMap[size]} color="#2f7dfa" />
      <span
        style={{
          fontFamily: "'Orbitron', 'Share Tech Mono', sans-serif",
          fontSize: fontSizeMap[size],
          letterSpacing: 2,
          fontWeight: 700,
          color: "#e8edf7",
        }}
      >
        CERBERUS<span style={{ color: "#22d3ee" }}>AI</span>
      </span>
    </div>
  );
}
