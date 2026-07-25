/**
 * Sidebar — Collapsible dashboard sidebar with navigation, user info, and logout.
 */

import { useNavigate, useLocation } from "react-router-dom";
import { useAuthStore } from "../../stores/authStore";
import { useUIStore } from "../../stores/uiStore";

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "📊", path: "/dashboard" },
  { id: "chat", label: "New Assessment", icon: "🤖", path: "/chat" },
  { id: "osint", label: "OSINT", icon: "🔍", path: "/osint" },
  { id: "redteam", label: "Red Team", icon: "🎯", path: "/redteam" },
  { id: "risk", label: "Risk Assessment", icon: "📈", path: "/risk" },
  { id: "reports", label: "Reports", icon: "📄", path: "/reports" },
  { id: "monitoring", label: "Monitoring", icon: "📡", path: "/monitoring" },
  { id: "notifications", label: "Notifications", icon: "🔔", path: "/notifications" },
  { id: "settings", label: "Settings", icon: "⚙️", path: "/settings" },
];

const adminItems = [
  { id: "admin", label: "Admin Panel", icon: "👑", path: "/admin" },
];

export default function Sidebar({ activeItem }: { activeItem?: string } = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();
  const { sidebarCollapsed, setSidebarCollapsed } = useUIStore();

  const handleLogout = () => { logout(); navigate("/login"); };

  return (
    <aside className={`${sidebarCollapsed ? "w-16" : "w-64"} h-screen bg-cerberus-gray-900 border-r border-cerberus-gray-700 flex flex-col fixed transition-all duration-300`}>
      {/* Header */}
      <div className="p-4 border-b border-cerberus-gray-700 flex items-center justify-between">
        {!sidebarCollapsed && (
          <div className="flex items-center gap-2">
            <span className="text-xl">🛡️</span>
            <span className="font-bold text-sm text-white">CERBERUS</span>
          </div>
        )}
        <button onClick={() => setSidebarCollapsed(!sidebarCollapsed)} className="text-gray-500 hover:text-white">
          {sidebarCollapsed ? "→" : "←"}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = activeItem ? activeItem === item.id : location.pathname.startsWith(item.path);
          return (
            <button
              key={item.id}
              onClick={() => navigate(item.path)}
              title={sidebarCollapsed ? item.label : undefined}
              className={`w-full flex items-center gap-3 ${sidebarCollapsed ? "px-4 justify-center" : "px-5"} py-2.5 text-sm transition-all
                ${isActive ? "text-cerberus-blue bg-cerberus-blue/10 border-r-2 border-cerberus-blue" : "text-gray-400 hover:text-white hover:bg-cerberus-gray-800"}`}
            >
              <span className="text-base">{item.icon}</span>
              {!sidebarCollapsed && <span>{item.label}</span>}
            </button>
          );
        })}

        {/* Admin section */}
        {(user?.role === "admin" || user?.role === "super_admin") && (
          <>
            <div className={`my-3 mx-4 border-t border-cerberus-gray-700 ${sidebarCollapsed ? "mx-2" : ""}`} />
            {adminItems.map((item) => (
              <button key={item.id} onClick={() => navigate(item.path)}
                className={`w-full flex items-center gap-3 ${sidebarCollapsed ? "px-4 justify-center" : "px-5"} py-2.5 text-sm text-gray-400 hover:text-white hover:bg-cerberus-gray-800 transition-all`}>
                <span className="text-base">{item.icon}</span>
                {!sidebarCollapsed && <span>{item.label}</span>}
              </button>
            ))}
          </>
        )}
      </nav>

      {/* User + Logout */}
      <div className="p-3 border-t border-cerberus-gray-700">
        {!sidebarCollapsed && user && (
          <div className="flex items-center gap-3 px-2 mb-3">
            <div className="w-8 h-8 rounded-full bg-cerberus-blue/20 flex items-center justify-center text-cerberus-blue text-xs font-bold">
              {user.full_name?.[0] || "U"}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-white truncate">{user.full_name}</p>
              <p className="text-[10px] text-gray-500 truncate">{user.email}</p>
            </div>
          </div>
        )}
        <button onClick={handleLogout}
          className={`w-full flex items-center gap-2 ${sidebarCollapsed ? "justify-center" : "px-3"} py-2 text-xs text-gray-500 hover:text-red-400 rounded transition-colors`}>
          <span>🚪</span>
          {!sidebarCollapsed && <span>Logout</span>}
        </button>
      </div>
    </aside>
  );
}
