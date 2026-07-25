/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        cerberus: {
          bg: "#03060c",
          panel: "rgba(10,16,28,0.7)",
          "panel-solid": "#0a101c",
          border: "#152238",
          "border-strong": "rgba(56,142,255,0.45)",
          text: "#e8edf7",
          muted: "#8493ac",
          dim: "#5b6a86",
          blue: "#2f7dfa",
          cyan: "#22d3ee",
          green: "#34e0a1",
          red: "#f4536b",
          yellow: "#e0b93a",
        },
      },
      fontFamily: {
        display: ["'Orbitron'", "'Share Tech Mono'", "sans-serif"],
        mono: ["'Share Tech Mono'", "'Courier New'", "monospace"],
      },
      animation: {
        float: "float 5s ease-in-out infinite",
        "float-slow": "floatSlow 6.5s ease-in-out infinite",
        drift: "drift 7s ease-in-out infinite",
        "fade-up": "fadeUp 0.7s ease both",
        "count-glow": "countGlow 3s ease-in-out infinite",
        spin: "spin 1s linear infinite",
      },
      keyframes: {
        float: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-14px)" } },
        floatSlow: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(10px)" } },
        drift: { "0%": { transform: "translate(0,0)" }, "50%": { transform: "translate(6px,-8px)" }, "100%": { transform: "translate(0,0)" } },
        fadeUp: { from: { opacity: 0, transform: "translateY(16px)" }, to: { opacity: 1, transform: "translateY(0)" } },
        countGlow: { "0%,100%": { textShadow: "0 0 18px rgba(47,125,250,0.35)" }, "50%": { textShadow: "0 0 28px rgba(34,211,238,0.55)" } },
        spin: { from: { transform: "rotate(0deg)" }, to: { transform: "rotate(360deg)" } },
      },
    },
  },
  plugins: [],
};
