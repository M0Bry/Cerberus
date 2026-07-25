/**
 * ErrorBoundary — Catches React errors.
 */
import { Component, ReactNode } from "react";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";
const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface Props { children: ReactNode; }
interface State { hasError: boolean; error: Error | null; }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, textAlign: "center", background: "#03060c", color: "#e8edf7", minHeight: "100vh", fontFamily: MONO }}>
          <h1 style={{ fontSize: 48 }}>⚠️</h1>
          <h2 style={{ fontFamily: DISPLAY, fontSize: 24, marginTop: 16 }}>Something went wrong</h2>
          <p style={{ color: "#8493ac", marginTop: 8 }}>{this.state.error?.message}</p>
          <button
            onClick={() => window.location.reload()}
            className="cta-btn"
            style={{ marginTop: 24, padding: "12px 24px" }}
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
