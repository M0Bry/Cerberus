/**
 * LandingSections — the static landing sections (new design):
 * Features, How It Works, Why, Stats, Pricing, Contact, Footer.
 * Ported from the new front-end's index.html.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { landingApi } from "../../api/landingApi";
import type { LandingStats } from "../../types";
import { checkContactField, checkEmail } from "../../utils/validators";
import CountUpValue from "./CountUpValue";

/* ─────────────────────────── Features ─────────────────────────── */

const FEATURES = [
  { icon: "fa-robot", title: "AI-Powered Testing", text: "Intelligent agent guides the entire engagement — from scope definition to final report — adapting to your industry." },
  { icon: "fa-search", title: "Automated OSINT", text: "Comprehensive open-source intelligence across domains, employees, technologies, and historical archives." },
  { icon: "fa-route", title: "Attack Path Planning", text: "AI constructs realistic attack paths tailored to your environment while respecting legal constraints." },
  { icon: "fa-lock", title: "Controlled Execution", text: "Non-destructive testing with continuous authorization checks and full audit logging of every action." },
  { icon: "fa-chart-line", title: "Business Risk Analysis", text: "Translates technical findings into clear business impact and prioritized remediation recommendations." },
  { icon: "fa-file-invoice", title: "Professional Reports", text: "Board-ready PDF reports with evidence, screenshots, risk scores, and actionable remediation guidance." },
  { icon: "fa-comments", title: "Conversational Interface", text: "Natural language interaction replaces complex forms. The AI learns your environment through dialogue." },
  { icon: "fa-scale-balanced", title: "Legal & Ethical by Design", text: "Every operation is authorized through agreements. Full compliance with ethical hacking principles." },
];

export function FeaturesSection() {
  return (
    <section className="section" id="features">
      <div className="container">
        <div className="fade-up" style={{ textAlign: "center", maxWidth: 680, margin: "0 auto" }}>
          <div className="section-label">Features</div>
          <h2 className="section-title">Why Organizations Choose Cerberus</h2>
          <p className="section-desc" style={{ margin: "0 auto" }}>
            Every phase of the security assessment is orchestrated by the Cerberus AI Agent — intelligent, adaptive, and
            fully compliant.
          </p>
        </div>
        <div className="features-grid">
          {FEATURES.map((f) => (
            <div className="feature-card fade-up" key={f.title}>
              <div className="feature-icon">
                <i className={`fas ${f.icon}`} />
              </div>
              <h3>{f.title}</h3>
              <p>{f.text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────── How it works ─────────────────────────── */

const STEPS = [
  { n: "01", title: "Register & Verify", text: "Account creation with organization details and secure OTP verification." },
  { n: "02", title: "AI Conversation", text: "Define scope through natural dialogue adapted to your industry." },
  { n: "03", title: "OSINT & Planning", text: "Automated intelligence collection and attack path generation." },
  { n: "04", title: "Controlled Testing", text: "Non-destructive assessments with live monitoring and discovery cards." },
  { n: "05", title: "Risk & Report", text: "Business risk scoring and professional PDF reports with evidence." },
];

export function HowItWorksSection() {
  return (
    <section className="section" id="how-it-works">
      <div className="container">
        <div className="fade-up" style={{ textAlign: "center", maxWidth: 760, margin: "0 auto" }}>
          <div className="section-label">The Process</div>
          <h2 className="section-title">From Conversation to Report</h2>
          <p className="section-desc" style={{ margin: "0 auto" }}>
            Cerberus transforms traditional penetration testing into an intelligent, guided workflow.
          </p>
        </div>
        <div className="steps">
          {STEPS.map((s) => (
            <div className="step fade-up" key={s.n}>
              <div className="step-number">{s.n}</div>
              <h3>{s.title}</h3>
              <p>{s.text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────── Why ─────────────────────────── */

const WHY_ITEMS = [
  { title: "No Deep Cyber Expertise Required", text: "The AI agent guides non-specialists through every stage with clarity." },
  { title: "Fully Auditable & Authorized", text: "Every interaction is logged and covered by legal agreements." },
  { title: "Adaptive to Your Industry", text: "Banking, software, healthcare — Cerberus adjusts its focus automatically." },
  { title: "Evidence-Based Results", text: "Screenshots, confidence scores, and reproducible findings in every report." },
];

export function WhySection() {
  return (
    <section className="section" id="why">
      <div className="container">
        <div className="why-grid">
          <div className="why-content fade-up">
            <div className="section-label">The Advantage</div>
            <h2 className="section-title">Built for Real-World Security Teams</h2>
            <p className="section-desc">
              Traditional penetration testing is expensive and requires specialized expertise. Cerberus democratizes
              advanced security assessment.
            </p>
            <ul className="why-list">
              {WHY_ITEMS.map((w) => (
                <li key={w.title}>
                  <div className="check">
                    <i className="fas fa-check" />
                  </div>
                  <div>
                    <h4>{w.title}</h4>
                    <p>{w.text}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────── Stats ─────────────────────────── */

const FALLBACK_STATS: LandingStats = { assessments: 31, vulnerabilities: 103, organizations: 3, reports: 0 };

export function StatsSection() {
  const { data } = useQuery({
    queryKey: ["landing-stats"],
    queryFn: async () => (await landingApi.getStats()).data as LandingStats,
    staleTime: Infinity,
    retry: 1,
  });
  const stats = data || FALLBACK_STATS;

  return (
    <section className="section">
      <div className="container">
        <div className="stats-grid">
          <div className="stat-card fade-up">
            <CountUpValue target={stats.assessments} className="number" />
            <div className="label">Assessments Completed</div>
            <span className="note">since our first engagement</span>
          </div>
          <div className="stat-card fade-up">
            <CountUpValue target={stats.vulnerabilities} className="number" />
            <div className="label">Vulnerabilities Disclosed</div>
            <span className="note">every one reported responsibly</span>
          </div>
          <div className="stat-card fade-up">
            <CountUpValue target={stats.organizations} className="number" />
            <div className="label">Organizations Protected</div>
            <span className="note">and counting, by referral</span>
          </div>
          <div className="stat-card fade-up">
            <CountUpValue target={100} suffix="%" className="number" initial="0%" />
            <div className="label">Authorized & Logged Operations</div>
            <span className="note">zero exceptions, ever</span>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────── Pricing ─────────────────────────── */

const PLANS = [
  {
    name: "Starter",
    price: "$59",
    per: "/mo",
    desc: "A first, honest look at your exposure.",
    limits: [
      <>
        <strong>1 assessment</strong> per month
      </>,
      <>
        <strong>1 active scope</strong> · up to 3 domains
      </>,
      <>
        Reports kept <strong>30 days</strong>
      </>,
      <>
        <strong>1 seat</strong> · email support, 48h reply
      </>,
    ],
    cta: "Get Started",
    to: "/register",
    kind: "outline" as const,
  },
  {
    name: "Professional",
    price: "$189",
    per: "/mo",
    desc: "For teams that assess on a rhythm, not once.",
    limits: [
      <>
        <strong>4 assessments</strong> per month
      </>,
      <>
        <strong>3 concurrent scopes</strong> · 10 domains each
      </>,
      <>
        Reports kept <strong>12 months</strong>
      </>,
      <>
        <strong>5 seats</strong> · priority support, 24h reply
      </>,
    ],
    cta: "Start Now",
    to: "/register",
    kind: "primary" as const,
    popular: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    per: "",
    desc: "For organizations with complex environments.",
    limits: [
      <>
        <strong>12+ assessments</strong> per month, custom volume
      </>,
      <>
        <strong>Unlimited scopes</strong> & domains
      </>,
      <>Custom retention · SSO · audit export</>,
      <>
        <strong>Unlimited seats</strong> · dedicated manager, 24/7 SLA
      </>,
    ],
    cta: "Contact Sales",
    to: "#contact",
    kind: "outline" as const,
  },
];

const PLAN_COMMON =
  "AI scoping conversation · automated OSINT · attack-path planning · controlled testing · business risk score · evidence PDF report";

export function PricingSection() {
  return (
    <section className="section" id="pricing">
      <div className="container">
        <div className="fade-up" style={{ textAlign: "center", maxWidth: 720, margin: "0 auto" }}>
          <div className="section-label">Transparent Pricing</div>
          <h2 className="section-title">Choose Your Pace</h2>
          <p className="section-desc" style={{ margin: "0 auto" }}>
            Every plan runs the identical Cerberus workflow — the same AI conversation, OSINT, controlled testing, and
            reporting. Plans differ only in how much you can use it, and how long you keep what it produces.
          </p>
        </div>
        <div className="pricing-grid">
          {PLANS.map((p) => (
            <div className={`pricing-card fade-up${p.popular ? " popular" : ""}`} key={p.name}>
              <div className="plan-name">{p.name}</div>
              <div className="plan-price">
                {p.price}
                {p.per && <span>{p.per}</span>}
              </div>
              <div className="plan-desc">{p.desc}</div>
              <ul className="plan-limits">
                {p.limits.map((l, i) => (
                  <li key={i}>
                    <i className="fas fa-check" />
                    <span>{l}</span>
                  </li>
                ))}
              </ul>
              <div className="plan-common">
                <span className="common-title">Full workflow on every plan</span>
                {PLAN_COMMON}
              </div>
              {p.to.startsWith("#") ? (
                <a href={p.to} className={`btn btn-${p.kind}`} style={{ width: "100%", marginTop: 22 }}>
                  {p.cta}
                </a>
              ) : (
                <Link to={p.to} className={`btn btn-${p.kind}`} style={{ width: "100%", marginTop: 22 }}>
                  {p.cta}
                </Link>
              )}
            </div>
          ))}
        </div>
        <p className="pricing-note">No plan changes how Cerberus works — only how often you unleash it.</p>
      </div>
    </section>
  );
}

/* ─────────────────────────── Contact ─────────────────────────── */

export function ContactSection() {
  const [form, setForm] = useState({ name: "", company: "", email: "", interest: "", message: "" });
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  const contactMutation = useMutation({
    mutationFn: async () =>
      (
        await landingApi.sendContact({
          name: form.name,
          email: form.email,
          subject: form.interest || "Inquiry",
          message: `${form.company ? `[${form.company}] ` : ""}${form.message}`,
        })
      ).data,
    onSuccess: () => {
      setSent(true);
      setError("");
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail
        || err?.response?.data?.error?.message
        || "Something went wrong sending your message. Please try again.";
      setError(Array.isArray(detail) ? detail[0]?.msg || "Please check your message and try again." : String(detail));
    },
  });

  const update = (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    setForm((p) => ({ ...p, [field]: e.target.value }));

  return (
    <section className="section" id="contact">
      <div className="container">
        <div className="fade-up" style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 16px" }}>
          <div className="section-label">Get In Touch</div>
          <h2 className="section-title">Let's Secure Your Organization</h2>
        </div>
        <div className="contact-grid">
          <div className="contact-info fade-up">
            <h3>We're here to help</h3>
            <p>Questions about the platform, custom enterprise proposals, or live demonstrations — our team is ready.</p>
            <div className="contact-item">
              <div className="icon">
                <i className="fas fa-envelope" />
              </div>
              <div>
                <h4>Email</h4>
                <span>contact@cerberus-ai.security</span>
              </div>
            </div>
            <div className="contact-item">
              <div className="icon">
                <i className="fas fa-headset" />
              </div>
              <div>
                <h4>Support</h4>
                <span>support@cerberus-ai.security</span>
              </div>
            </div>
            <div className="contact-item">
              <div className="icon">
                <i className="fas fa-building" />
              </div>
              <div>
                <h4>Enterprise Sales</h4>
                <span>enterprise@cerberus-ai.security</span>
              </div>
            </div>
            <div className="contact-item">
              <div className="icon">
                <i className="fas fa-clock" />
              </div>
              <div>
                <h4>Response Time</h4>
                <span>Usually within 24 hours</span>
              </div>
            </div>
          </div>

          <div className="contact-form fade-up">
            {sent ? (
              <div className="alert show ok" style={{ padding: 24 }}>
                <i className="fas fa-circle-check" /> Thank you — your message has been sent. Our team will get back to you.
              </div>
            ) : (
              <form
                noValidate
                onSubmit={(e) => {
                  e.preventDefault();
                  setError("");
                  // Client-side validation (the backend re-checks everything).
                  const nameErr = checkContactField("name", form.name);
                  if (nameErr) return setError(nameErr);
                  const emailErr = checkEmail(form.email);
                  if (emailErr) return setError(emailErr);
                  const messageErr = checkContactField("message", form.message);
                  if (messageErr) return setError(messageErr);
                  contactMutation.mutate();
                }}
              >
                <div className="form-row">
                  <div className="form-group">
                    <label>Full Name</label>
                    <input type="text" required minLength={2} maxLength={120} placeholder="John Doe" value={form.name} onChange={update("name")} />
                  </div>
                  <div className="form-group">
                    <label>Company</label>
                    <input type="text" required placeholder="Acme Corp" value={form.company} onChange={update("company")} />
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>Work Email</label>
                    <input type="email" required placeholder="john@acme.com" value={form.email} onChange={update("email")} />
                  </div>
                  <div className="form-group">
                    <label>Interest</label>
                    <select required value={form.interest} onChange={update("interest")}>
                      <option value="">Select...</option>
                      <option>Product Demo</option>
                      <option>Pricing Inquiry</option>
                      <option>Enterprise Partnership</option>
                      <option>Technical Questions</option>
                    </select>
                  </div>
                </div>
                <div className="form-group">
                  <label>Message</label>
                  <textarea required placeholder="Tell us about your security assessment needs..." value={form.message} onChange={update("message")} />
                </div>
                {error && <div className="alert show err">{error}</div>}
                <button type="submit" className="btn btn-primary" style={{ width: "100%" }} disabled={contactMutation.isPending}>
                  <i className="fas fa-paper-plane" /> {contactMutation.isPending ? "Sending…" : "Send Message"}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────── Footer ─────────────────────────── */

export function LandingFooter() {
  const [subscribed, setSubscribed] = useState(false);

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-grid">
          <div className="footer-brand">
            <Link to="/" className="logo">
              <img src="/assets/newfront/logo-cerberus.png" alt="Cerberus" className="logo-img" />
              <div className="logo-text">
                Cerberus<span>AI</span>
              </div>
            </Link>
            <p>
              Intelligent cybersecurity platform that automates the entire penetration testing lifecycle with AI
              precision and ethical rigor.
            </p>
            <div className="social-links">
              <a href="#" aria-label="X / Twitter">
                <i className="fab fa-x-twitter" />
              </a>
              <a href="#" aria-label="LinkedIn">
                <i className="fab fa-linkedin-in" />
              </a>
              <a href="#" aria-label="GitHub">
                <i className="fab fa-github" />
              </a>
              <a href="#" aria-label="Discord">
                <i className="fab fa-discord" />
              </a>
            </div>
          </div>

          <div className="footer-col">
            <h4>Platform</h4>
            <ul>
              <li>
                <a href="#features">Features</a>
              </li>
              <li>
                <a href="#how-it-works">How It Works</a>
              </li>
              <li>
                <a href="#pricing">Pricing</a>
              </li>
              <li>
                <a href="#">API Docs</a>
              </li>
              <li>
                <a href="#">Integrations</a>
              </li>
            </ul>
          </div>

          <div className="footer-col">
            <h4>Resources</h4>
            <ul>
              <li>
                <a href="#">Documentation</a>
              </li>
              <li>
                <a href="#">Security Whitepaper</a>
              </li>
              <li>
                <a href="#">Case Studies</a>
              </li>
              <li>
                <a href="#">Blog</a>
              </li>
              <li>
                <a href="#">Changelog</a>
              </li>
            </ul>
          </div>

          <div className="footer-col">
            <h4>Company</h4>
            <ul>
              <li>
                <a href="#">About Us</a>
              </li>
              <li>
                <a href="#contact">Contact</a>
              </li>
              <li>
                <a href="#">Careers</a>
              </li>
              <li>
                <a href="#">Partners</a>
              </li>
              <li>
                <a href="#">Press Kit</a>
              </li>
            </ul>
          </div>

          <div className="footer-col">
            <h4>Stay Updated</h4>
            <p>Latest on AI-driven security.</p>
            {subscribed ? (
              <p className="alert show ok" style={{ padding: "10px 12px", fontSize: ".8rem" }}>
                Subscribed — thank you!
              </p>
            ) : (
              <form
                className="newsletter-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  setSubscribed(true);
                }}
              >
                <input type="email" placeholder="Your email" required aria-label="Email" />
                <button type="submit" aria-label="Subscribe">
                  <i className="fas fa-arrow-right" />
                </button>
              </form>
            )}
          </div>
        </div>

        <div className="footer-bottom">
          <div>© 2026 Cerberus AI. All rights reserved. Ethical hacking. Legal compliance.</div>
          <div className="footer-bottom-links">
            <Link to="/privacy">Privacy Policy</Link>
            <Link to="/terms">Terms of Service</Link>
            <Link to="/compliance">Acceptable Use</Link>
            <Link to="/compliance">Security</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
