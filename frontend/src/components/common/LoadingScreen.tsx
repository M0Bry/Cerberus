/**
 * LoadingScreen — Cerberus-branded loading animation.
 */
const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";

const spinKeyframes = `
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
`;

const floatKeyframes = `
  @keyframes float {
    0% { transform: translateX(-100%); }
    50% { transform: translateX(20%); }
    100% { transform: translateX(200%); }
  }
`;

export default function LoadingScreen() {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "#03060c",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
      }}
    >
      {/* Inject the necessary keyframes */}
      <style>{spinKeyframes}</style>
      <style>{floatKeyframes}</style>

      <div style={{ textAlign: "center" }}>
        <div
          style={{
            width: 60,
            height: 60,
            borderRadius: "50%",
            border: "2px solid rgba(47,125,250,0.3)",
            borderTopColor: "#2f7dfa",
            animation: "spin 1s linear infinite",
            margin: "0 auto 24px",
          }}
        />
        <p
          style={{
            fontFamily: DISPLAY,
            fontSize: 14,
            color: "#22d3ee",
            letterSpacing: 2,
          }}
        >
          INITIALIZING CERBERUS AI...
        </p>
        <div
          style={{
            width: 192,
            height: 3,
            background: "#152238",
            borderRadius: 4,
            margin: "16px auto 0",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              width: "40%",
              height: "100%",
              background: "linear-gradient(90deg, #2f7dfa, #22d3ee)",
              borderRadius: 4,
              animation: "float 2s ease-in-out infinite",
            }}
          />
        </div>
      </div>
    </div>
  );
}
