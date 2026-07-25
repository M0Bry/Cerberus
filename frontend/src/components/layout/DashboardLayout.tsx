/**
 * DashboardLayout — Exact sidebar + main layout from the reference design.
 */
import { ReactNode, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Plus, FolderKanban, ClipboardList, Bell,
  Settings, LogOut, Shield,
} from "lucide-react";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";
const MONO = "'Share Tech Mono', 'Courier New', monospace";

const SIDEBAR_ITEMS = [
  { icon: LayoutDashboard, label: "Dashboard", path: "/dashboard" },
  { icon: Plus, label: "New Assessment", path: "/chat" },
  { icon: FolderKanban, label: "My Assessments", path: "/assessments" },
  { icon: ClipboardList, label: "Reports", path: "/reports" },
  { icon: Bell, label: "Notifications", path: "/notifications" },
  { icon: Settings, label: "Profile", path: "/profile" },
];

interface DashboardLayoutProps {
  children: ReactNode;
  activeItem?: string;
}

export default function DashboardLayout({ children, activeItem }: DashboardLayoutProps) {
  const navigate = useNavigate();
  const [active, setActive] = useState(activeItem || "Dashboard");

  return (
    <div
      style={{
        background: "#03060c",
        color: "#e8edf7",
        minHeight: "100vh",
        fontFamily: MONO,
        position: "relative",
        display: "flex",
      }}
    >
      {/* Dot background */}
      <div className="dot-bg" />

      {/* Sidebar */}
      <aside
        style={{
          position: "relative",
          zIndex: 1,
          width: 230,
          borderRight: "1px solid #152238",
          background: "rgba(6,10,20,0.7)",
          padding: "22px 14px",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div style={{ padding: "0 8px 22px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Shield size={18} color="#2f7dfa" />
            <span
              style={{
                fontFamily: DISPLAY,
                fontSize: 14,
                letterSpacing: 2,
                fontWeight: 700,
              }}
            >
              CERBERUS<span style={{ color: "#22d3ee" }}>AI</span>
            </span>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 3, flex: 1 }}>
          {SIDEBAR_ITEMS.map((item) => {
            const isActive = active === item.label;
            return (
              <div
                key={item.label}
                onClick={() => {
                  setActive(item.label);
                  navigate(item.path);
                }}
                className="side-link"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "10px 12px",
                  borderRadius: 9,
                  cursor: "pointer",
                  fontSize: 13,
                  color: isActive ? "#e8edf7" : "#8493ac",
                  background: isActive ? "rgba(47,125,250,0.14)" : "transparent",
                  borderLeft: isActive ? "2px solid #2f7dfa" : "2px solid transparent",
                }}
              >
                <item.icon size={15} color={isActive ? "#22d3ee" : "#5b6a86"} />
                {item.label}
              </div>
            );
          })}
        </div>

        {/* Logout */}
        <div
          onClick={() => {
            localStorage.clear();
            navigate("/login");
          }}
          className="side-link"
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 12px",
            borderRadius: 9,
            cursor: "pointer",
            fontSize: 13,
            color: "#8493ac",
            borderTop: "1px solid #152238",
            marginTop: 8,
            paddingTop: 16,
          }}
        >
          <LogOut size={15} color="#5b6a86" />
          Logout
        </div>
      </aside>

      {/* Main content */}
      <main
        style={{
          position: "relative",
          zIndex: 1,
          flex: 1,
          padding: "32px 36px",
          overflowY: "auto",
        }}
      >
        {children}
      </main>
    </div>
  );
}
