/**
 * Sidebar — shared app sidebar: icon rail by default, logo toggles open/close.
 *
 * Ported from the new front-end's js/sidebar.js.
 *  - 4 nav items (AI Chat, Assessments, Reports, Notifications) with inline SVG
 *  - collapse state lives in AppShell (adds "sb-open" to the .app-shell element),
 *    persisted in localStorage ("cerberus_sb")
 *  - footer avatar + account popover (Subscription, Profile, Settings, Help, Sign Out)
 *  - user info comes from the auth store (was localStorage "cerberus_acct" in the mock)
 */
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";
import { authApi } from "../../api/authApi";
import { useAccess } from "../../hooks/useAccess";

const NAV = [
  {
    to: "/chat",
    label: "AI Chat",
    svg: (
      <svg viewBox="0 0 24 24" aria-hidden="true" className="sb-ico">
        <path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
        <path d="M18.4 2.6a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4 9.4-9.4Z" />
      </svg>
    ),
  },
  {
    to: "/assessments",
    label: "Assessments",
    svg: (
      <svg viewBox="0 0 24 24" aria-hidden="true" className="sb-ico">
        <path d="m3 17 2 2 4-4" />
        <path d="m3 7 2 2 4-4" />
        <path d="M13 6h8" />
        <path d="M13 12h8" />
        <path d="M13 18h8" />
      </svg>
    ),
  },
  {
    to: "/reports",
    label: "Reports",
    svg: (
      <svg viewBox="0 0 24 24" aria-hidden="true" className="sb-ico">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
        <path d="M14 2v6h6" />
        <path d="M8 13h8" />
        <path d="M8 17h5" />
      </svg>
    ),
  },
  {
    to: "/notifications",
    label: "Notifications",
    svg: (
      <svg viewBox="0 0 24 24" aria-hidden="true" className="sb-ico">
        <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
        <path d="M10.3 21a1.9 1.9 0 0 0 3.4 0" />
      </svg>
    ),
  },
];

interface SidebarProps {
  open: boolean;
  onToggle: () => void;
  onCollapse: () => void;
}

export default function Sidebar({ open, onToggle, onCollapse }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();
  const [menuOpen, setMenuOpen] = useState(false);
  const meRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const name = user?.full_name || "John Doe";
  const email = user?.email || "";
  const photo = user?.avatar_url || "";
  const initial = (name.trim()[0] || "J").toUpperCase();

  /* live access state for the account popover badge:
     paid → plan name · trial → "Free · Xd" · suspended → "Suspended" */
  const { data: access } = useAccess(!!user);
  const planLabel =
    access?.state === "suspended"
      ? "Suspended"
      : access?.state === "paid"
        ? access.plan_name || "Admin"
        : access
          ? `Free · ${access.trial_days_left}d`
          : "Free";

  const handleSignOut = async () => {
    try {
      await authApi.logout();
    } catch {
      /* server may be unreachable — clear local session regardless */
    }
    logout();
    navigate("/login");
  };

  const goPricing = () => {
    setMenuOpen(false);
    navigate("/billing");
  };

  /* close the account popover on outside click / Escape */
  useEffect(() => {
    if (!menuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (
        meRef.current &&
        menuRef.current &&
        !meRef.current.contains(e.target as Node) &&
        !menuRef.current.contains(e.target as Node)
      ) {
        setMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("click", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("click", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  const isActive = (to: string) =>
    to === "/chat"
      ? location.pathname === "/chat" || /^\/chat\//.test(location.pathname)
      : location.pathname.startsWith(to);

  const menuStyle: React.CSSProperties | undefined = (() => {
    if (!menuOpen || !meRef.current) return undefined;
    const r = meRef.current.getBoundingClientRect();
    const style: React.CSSProperties = { position: "fixed", left: r.right + 10 };
    if (r.top < innerHeight / 2) style.top = Math.max(8, r.top);
    else style.bottom = innerHeight - r.bottom;
    return style;
  })();

  return (
    <>
      <aside className="sidebar">
        <div className="sb-top">
          <button
            type="button"
            className="sb-logo-btn"
            onClick={onToggle}
            aria-label="Open or close sidebar"
            aria-expanded={open ? "true" : "false"}
            title="Open or close sidebar"
          >
            <img className="sb-brand" src="/assets/newfront/logo-cerberus.png" alt="" />
          </button>
          <button type="button" className="sb-collapse" title="Collapse" aria-label="Collapse" onClick={onCollapse}>
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M9 3v18" />
            </svg>
          </button>
        </div>

        <nav className="sb-nav">
          {NAV.map((n) => (
            <Link key={n.to} to={n.to} title={n.label} className={isActive(n.to) ? "active" : ""}>
              {n.svg}
              <span className="sb-lbl">{n.label}</span>
            </Link>
          ))}
        </nav>

        <div className="sb-foot">
          <button
            ref={meRef}
            type="button"
            className="sb-me"
            aria-haspopup="menu"
            aria-expanded={menuOpen ? "true" : "false"}
            aria-label="Account menu"
            title="Account"
            onClick={(e) => {
              e.stopPropagation();
              setMenuOpen((v) => !v);
            }}
          >
            {photo ? (
              <img className="sb-av sb-av-img" src={photo} alt="" />
            ) : (
              <span className="sb-av">{initial}</span>
            )}
            <span className="sb-me-name">{name}</span>
          </button>
        </div>
      </aside>

      {menuOpen && (
        <div ref={menuRef} className="sb-menu" role="menu" style={menuStyle} onClick={(e) => e.stopPropagation()}>
          <div className="sb-menu-head">
            <div className="sb-menu-name">{name}</div>
            <div className="sb-menu-mail">{email}</div>
          </div>
          <button type="button" className="sb-menu-row" role="menuitem" onClick={goPricing}>
            <span>Subscription</span>
            <b className="sb-menu-plan">{planLabel}</b>
          </button>
          <Link className="sb-menu-row" role="menuitem" to="/profile">
            <span>Profile</span>
            <i className="fas fa-chevron-right" />
          </Link>
          <Link className="sb-menu-row" role="menuitem" to="/settings">
            <span>Settings</span>
            <i className="fas fa-chevron-right" />
          </Link>
          <button type="button" className="sb-menu-row sb-menu-soon" role="menuitem">
            <span>Help</span>
            <i className="fas fa-chevron-right" />
          </button>
          <button type="button" className="sb-menu-row sb-menu-out" role="menuitem" onClick={handleSignOut}>
            <span>Sign Out</span>
            <i className="fas fa-arrow-right-from-bracket" />
          </button>
        </div>
      )}
    </>
  );
}
