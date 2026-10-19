/**
 * HeroSection — hero with breach rain, cursor spotlight and animated stats.
 * Ported from the new front-end's index.html (hero block) + canvas effects.
 */
import { Link } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";
import HeroRain from "../effects/HeroRain";
import CursorSpotlight from "../effects/CursorSpotlight";
import CountUpValue from "./CountUpValue";

const HERO_STATS = [
  { target: 30, prefix: "+", label: "Assessment Run" },
  { target: 103, prefix: "+", label: "Vulnerabilities Found" },
  { target: 3, prefix: "+", label: "Organizations Protected" },
];

export default function HeroSection() {
  const { isAuthenticated } = useAuthStore();
  const cta = isAuthenticated ? "/chat" : "/register";

  return (
    <section className="hero">
      <div className="hero-bg" aria-hidden="true">
        <HeroRain />
        <div className="hero-blob" />
        <CursorSpotlight />
      </div>
      <div className="hero-art-wrap">
        <img className="hero-art" src="/assets/newfront/hero.png" alt="Cerberus — the three-headed hound" />
      </div>
      <div className="container">
        <div className="hero-content">
          <div className="hero-text fade-up">
            <div className="hero-badge">
              <span className="dot" /> Cyber-Security Agent
            </div>
            <h1>
              The Devil
              <br />
              Who Chooses
              <br />
              <span className="gradient">Not To Dance</span>
            </h1>
            <p className="hero-desc">
              Cerberus AI automates the entire penetration testing lifecycle — from OSINT and attack path planning to
              controlled testing, risk analysis, and professional reporting. No advanced expertise required.
            </p>
            <div className="hero-actions">
              <Link to={cta} className="btn btn-primary">
                <i className="fas fa-rocket" /> Start Registration
              </Link>
              <a href="#how-it-works" className="btn btn-outline">
                <i className="fas fa-play-circle" /> Discover How It Works
              </a>
            </div>
            <div className="hero-stats">
              {HERO_STATS.map((s) => (
                <div className="hero-stat" key={s.label}>
                  <CountUpValue target={s.target} prefix={s.prefix} className="value" initial="+0" />
                  <div className="label">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
