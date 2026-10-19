/**
 * Landing Page (new design) — ported from the new front-end's index.html.
 *
 * Composes: NetworkGrid backdrop, navbar, hero (breach rain + cursor
 * spotlight), features, process, why, stats (live /public/stats), pricing,
 * contact (POST /public/contact) and footer.
 */
import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import NetworkGrid from "../components/effects/NetworkGrid";
import LandingNav from "../components/landing/LandingNav";
import HeroSection from "../components/landing/HeroSection";
import {
  FeaturesSection,
  HowItWorksSection,
  WhySection,
  StatsSection,
  PricingSection,
  ContactSection,
  LandingFooter,
} from "../components/landing/LandingSections";

export default function LandingPage() {
  const rootRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  /* ── exact in-page anchor scrolling ─────────────────────────────────────
     The section top lands FLUSH under the navbar, pixel-precise: the target
     offset is computed from the nav's real content height at click time
     (scrolled nav = content + 20px padding + 1px border), so it is exact on
     every viewport — no scroll-margin guessing, no "a bit high" landing.
     Covers the navbar links, mobile menu, hero CTA, pricing CTA, footer. */
  const scrollExact = (id: string) => {
    const target = document.getElementById(id);
    if (!target) return;
    const nav = document.getElementById("navbar");
    const inner = nav?.querySelector(".nav-inner");
    // content height is stable even while the padding transition runs
    const navH = (inner ? inner.getBoundingClientRect().height : 50) + 21;
    const top = Math.max(0, target.getBoundingClientRect().top + window.scrollY - navH);
    window.scrollTo({ top, behavior: "smooth" });
    history.replaceState(null, "", `#${id}`);
  };

  useEffect(() => {
    const onAnchorClick = (e: MouseEvent) => {
      const a = (e.target as HTMLElement | null)?.closest?.('a[href^="#"]');
      if (!a) return;
      const id = a.getAttribute("href")?.slice(1) || "";
      if (!id || !document.getElementById(id)) return; // plain "#" keeps native behaviour
      e.preventDefault();
      scrollExact(id);
    };
    document.addEventListener("click", onAnchorClick);
    return () => document.removeEventListener("click", onAnchorClick);
  }, []);

  /* deep-link support: {state: {scrollTo: "contact"}} (used by the 404 page) */
  useEffect(() => {
    const target = (location.state as { scrollTo?: string } | null)?.scrollTo;
    if (!target) return;
    const t = window.setTimeout(() => scrollExact(target), 250);
    return () => window.clearTimeout(t);
  }, [location.state]);

  /* reveal-on-scroll for every .fade-up element (matches js/main.js behaviour) */
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const els = Array.from(root.querySelectorAll<HTMLElement>(".fade-up"));
    if (!els.length) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            obs.unobserve(e.target);
          }
        });
      },
      { threshold: 0.1 }
    );
    els.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div ref={rootRef} className="landing-root">
      <NetworkGrid />
      <LandingNav />
      <main>
        <HeroSection />
        <FeaturesSection />
        <HowItWorksSection />
        <WhySection />
        <StatsSection />
        <PricingSection />
        <ContactSection />
      </main>
      <LandingFooter />
    </div>
  );
}
