/**
 * LandingNav — public navbar + mobile menu (new design).
 * Ported from the new front-end's index.html + js/main.js.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";

const LINKS = [
  { href: "#features", label: "Features" },
  { href: "#how-it-works", label: "How It Works" },
  { href: "#why", label: "Why Cerberus?" },
  { href: "#pricing", label: "Pricing" },
  { href: "#contact", label: "Contact" },
];

export default function LandingNav() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const { isAuthenticated } = useAuthStore();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const closeMenu = () => setMenuOpen(false);

  return (
    <>
      <nav className={`navbar${scrolled ? " scrolled" : ""}`} id="navbar">
        <div className="container nav-inner">
          <Link to="/" className="logo">
            <img src="/assets/newfront/logo-cerberus.png" alt="Cerberus AI" className="logo-img" />
            <div className="logo-text">
              Cerberus<span>AI</span>
            </div>
          </Link>
          <ul className="nav-links">
            {LINKS.map((l) => (
              <li key={l.href}>
                <a href={l.href}>{l.label}</a>
              </li>
            ))}
          </ul>
          <div className="nav-cta">
            <Link to={isAuthenticated ? "/chat" : "/login"} className="btn btn-ghost">
              {isAuthenticated ? "Open App" : "Log In"}
            </Link>
            <Link to={isAuthenticated ? "/chat" : "/register"} className="btn btn-primary">
              {isAuthenticated ? "Get Started" : "Sign Up"}
            </Link>
          </div>
          <button className="mobile-toggle" aria-label="Open menu" onClick={() => setMenuOpen((v) => !v)}>
            <i className="fas fa-bars" />
          </button>
        </div>
      </nav>

      <div className={`mobile-overlay${menuOpen ? " open" : ""}`} onClick={closeMenu} />
      <div className={`mobile-menu${menuOpen ? " open" : ""}`}>
        {LINKS.map((l) => (
          <a key={l.href} href={l.href} onClick={closeMenu}>
            {l.label}
          </a>
        ))}
        <Link to={isAuthenticated ? "/chat" : "/login"} style={{ marginTop: 16, color: "var(--accent)" }} onClick={closeMenu}>
          {isAuthenticated ? "Open App" : "Log In"}
        </Link>
        <Link to={isAuthenticated ? "/chat" : "/register"} style={{ color: "var(--accent)" }} onClick={closeMenu}>
          Get Started
        </Link>
      </div>
    </>
  );
}
