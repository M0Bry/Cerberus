/**
 * LegalShell — shared chrome for the legal pages (new design identity):
 * landing navbar + a centered reading column + footer.
 */
import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useReveal } from "../../hooks/useReveal";
import LandingNav from "./LandingNav";
import { LandingFooter } from "./LandingSections";

interface LegalShellProps {
  label: string;
  title: string;
  intro?: string;
  children: ReactNode;
}

export default function LegalShell({ label, title, intro, children }: LegalShellProps) {
  const ref = useReveal<HTMLDivElement>();

  return (
    <div ref={ref}>
      <LandingNav />
      <main className="section" style={{ paddingTop: 120 }}>
        <div className="container" style={{ maxWidth: 820 }}>
          <div className="fade-up" style={{ textAlign: "center", marginBottom: 28 }}>
            <div className="section-label">{label}</div>
            <h1 className="section-title">{title}</h1>
            {intro && <p className="section-desc" style={{ margin: "0 auto" }}>{intro}</p>}
          </div>
          <div className="panel fade-up" style={{ padding: "36px 40px" }}>
            {children}
          </div>
          <p className="auth-foot" style={{ textAlign: "center", marginTop: 22 }}>
            <Link to="/">← Back to Cerberus AI</Link>
          </p>
        </div>
      </main>
      <LandingFooter />
    </div>
  );
}
