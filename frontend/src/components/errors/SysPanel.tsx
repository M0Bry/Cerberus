/**
 * SysPanel — shared shell for the system/error pages (new design).
 * Mirrors the new front-end's 404/unauthorized/server-error/maintenance pages:
 * embers canvas + auth-glow behind, logo + back link, .sys-panel content.
 */
import { ReactNode } from "react";
import { Link } from "react-router-dom";
import AuthEmbers from "../effects/AuthEmbers";

interface SysPanelProps {
  icon: string;
  tag: ReactNode;
  title: string;
  sub: string;
  actions: ReactNode;
  backTo?: string;
  backLabel?: string;
}

export default function SysPanel({ icon, tag, title, sub, actions, backTo = "/", backLabel = "Back" }: SysPanelProps) {
  return (
    <>
      <div className="auth-glow" aria-hidden="true" />
      <AuthEmbers />
      <div className="auth-wrap">
        <Link to="/" className="auth-logo">
          <img src="/assets/newfront/logo-cerberus.png" alt="Cerberus AI" />
          <div className="logo-text">
            Cerberus<span>AI</span>
          </div>
        </Link>
        <Link to={backTo} className="auth-back">
          <i className="fas fa-arrow-left" /> {backLabel}
        </Link>

        <main className="sys-panel fade-up visible">
          <div className="sys-icon">
            <i className={`fas ${icon}`} />
          </div>
          <p className="sys-tag">{tag}</p>
          <h1 className="auth-title sys-title">{title}</h1>
          <p className="sys-sub">{sub}</p>
          <div className="sys-actions">{actions}</div>
        </main>
      </div>
    </>
  );
}
