/**
 * TopNav — Exact navigation bar from the reference design.
 */
import { useNavigate } from "react-router-dom";
import CerberusLogo from "../common/CerberusLogo";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

export default function Navbar() {
  const navigate = useNavigate();

  return (
    <nav
      style={{
        position: "relative",
        zIndex: 2,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "16px 32px",
        borderBottom: "1px solid #152238",
        background: "rgba(3,6,12,0.7)",
        backdropFilter: "blur(8px)",
      }}
    >
      <div onClick={() => navigate("/")} style={{ cursor: "pointer" }}>
        <CerberusLogo />
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 30, fontSize: 13.5 }}>
        <span className="nav-link" style={{ color: "#8493ac" }} onClick={() => navigate("/")}>
          Why Cerberus
        </span>
        <span className="nav-link" style={{ color: "#8493ac" }} onClick={() => navigate("/#how")}>
          How It Works
        </span>
        <span className="nav-link" style={{ color: "#8493ac" }} onClick={() => navigate("/login")}>
          Login
        </span>
      </div>

      <button
        className="cta-btn sheen"
        onClick={() => navigate("/register")}
        style={{
          color: "white",
          border: "none",
          borderRadius: 8,
          padding: "10px 22px",
          fontSize: 13.5,
          fontWeight: 700,
          fontFamily: MONO,
        }}
      >
        Get Started
      </button>
    </nav>
  );
}
