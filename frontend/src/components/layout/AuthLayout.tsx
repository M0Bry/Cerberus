/**
 * AuthLayout — shared wrapper for the auth pages (new design).
 *
 * Mirrors the new front-end's auth pages markup:
 *   .auth-glow + AuthEmbers canvas behind, .auth-wrap with logo + back link
 *   and the page panel (children).
 */
import { ReactNode } from "react";
import { Link } from "react-router-dom";
import AuthEmbers from "../effects/AuthEmbers";

interface AuthLayoutProps {
  children: ReactNode;
  /** Where the "back" link points. Defaults to the login page. */
  backTo?: string;
  backLabel?: string;
}

export default function AuthLayout({ children, backTo = "/login", backLabel = "Log In" }: AuthLayoutProps) {
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
        {children}
      </div>
    </>
  );
}
