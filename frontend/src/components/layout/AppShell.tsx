/**
 * AppShell — authenticated app layout (new design).
 *
 * Structure mirrors the new front-end's HTML:
 *   <div class="app-shell [sb-open]">
 *     <aside class="sidebar">…</aside>   (injected by Sidebar)
 *     <main class="main">…page…</main>   (each page renders its own .topbar)
 *
 * The "sb-open" state is persisted in localStorage ("cerberus_sb"),
 * matching the mock's behaviour.
 */
import { Outlet, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import Sidebar from "./Sidebar";

export default function AppShell() {
  const location = useLocation();
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem("cerberus_sb") === "open";
    } catch {
      return false;
    }
  });

  /* auto-collapse on small screens when navigating between pages */
  useEffect(() => {
    if (innerWidth <= 768) {
      setOpen(false);
      try {
        localStorage.setItem("cerberus_sb", "closed");
      } catch {
        /* ignore */
      }
    }
  }, [location.pathname]);

  const persist = (v: boolean) => {
    try {
      localStorage.setItem("cerberus_sb", v ? "open" : "closed");
    } catch {
      /* ignore */
    }
  };

  return (
    <div className={open ? "app-shell sb-open" : "app-shell"}>
      <Sidebar
        open={open}
        onToggle={() => {
          setOpen((v) => {
            persist(!v);
            return !v;
          });
        }}
        onCollapse={() => {
          setOpen(false);
          persist(false);
        }}
      />
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
