/**
 * LoadingScreen — Suspense fallback (new design identity).
 *
 * Shown briefly while a route chunk loads. Self-contained: inline styles +
 * its own keyframes (unique names), new blood-red palette, Teko display font.
 * Honors prefers-reduced-motion.
 */
const TOKENS = {
  bg: "#111112",
  blood: "#7c0a12",
  accent: "#cf2731",
  ember: "#ff7a45",
  text: "#e8e6e3",
  muted: "#8a8a8f",
};

const keyframes = `
@keyframes csb-spin { to { transform: rotate(360deg); } }
@keyframes csb-sweep {
  0% { transform: translateX(-100%); }
  55% { transform: translateX(45%); }
  100% { transform: translateX(220%); }
}
@keyframes csb-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.55; }
}
@media (prefers-reduced-motion: reduce) {
  .csb-spin, .csb-sweep, .csb-pulse { animation: none !important; }
}
`;

export default function LoadingScreen() {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: TOKENS.bg,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
      }}
    >
      <style>{keyframes}</style>

      <div style={{ textAlign: "center" }}>
        <img
          src="/assets/newfront/logo-cerberus.png"
          alt=""
          className="csb-pulse"
          style={{
            width: 64,
            height: 64,
            objectFit: "contain",
            margin: "0 auto 18px",
            display: "block",
            animation: "csb-pulse 1.6s ease-in-out infinite",
          }}
        />
        <p
          style={{
            fontFamily: "'Teko', 'Merriweather', serif",
            fontSize: 22,
            fontWeight: 600,
            letterSpacing: "6px",
            textTransform: "uppercase",
            color: TOKENS.text,
            margin: 0,
          }}
        >
          Cerberus<span style={{ color: TOKENS.accent }}> AI</span>
        </p>
        <p
          style={{
            fontFamily: "'Teko', serif",
            fontSize: 12,
            letterSpacing: "4px",
            textTransform: "uppercase",
            color: TOKENS.muted,
            margin: "6px 0 0",
          }}
        >
          Loading
        </p>

        <div
          style={{
            width: 192,
            height: 2,
            background: "rgba(207,39,49,0.18)",
            borderRadius: 2,
            margin: "18px auto 0",
            overflow: "hidden",
          }}
        >
          <div
            className="csb-sweep"
            style={{
              width: "40%",
              height: "100%",
              background: `linear-gradient(90deg, ${TOKENS.blood}, ${TOKENS.accent} 60%, ${TOKENS.ember})`,
              borderRadius: 2,
              animation: "csb-sweep 1.8s ease-in-out infinite",
            }}
          />
        </div>
      </div>
    </div>
  );
}
