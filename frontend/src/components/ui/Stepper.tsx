/**
 * Stepper — Step indicator matching the reference design.
 */
import { CheckCircle2 } from "lucide-react";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";
const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface Step {
  label: string;
  status: "completed" | "active" | "upcoming";
}

export default function Stepper({ steps }: { steps: Step[] }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
      {steps.map((step, i) => (
        <div key={step.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: "50%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 12,
              fontWeight: 700,
              fontFamily: DISPLAY,
              border: `1.5px solid ${
                step.status === "completed" ? "#34e0a1"
                : step.status === "active" ? "#2f7dfa"
                : "#152238"
              }`,
              background: step.status === "completed" ? "rgba(52,224,161,0.15)"
                : step.status === "active" ? "rgba(47,125,250,0.15)"
                : "transparent",
              color: step.status === "completed" ? "#34e0a1"
                : step.status === "active" ? "#2f7dfa"
                : "#5b6a86",
            }}
          >
            {step.status === "completed" ? "✓" : i + 1}
          </div>
          <span style={{ fontSize: 11, color: step.status === "active" ? "#e8edf7" : "#5b6a86", fontFamily: MONO }}>
            {step.label}
          </span>
          {i < steps.length - 1 && (
            <div style={{ width: 32, height: 1, background: step.status === "completed" ? "#34e0a1" : "#152238" }} />
          )}
        </div>
      ))}
    </div>
  );
}
