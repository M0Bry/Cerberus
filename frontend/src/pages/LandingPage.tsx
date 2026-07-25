/**
 * Landing Page — PDF Pages 1-2: Complete public-facing introduction.
 */

import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import ParticleBackground from "../components/common/ParticleBackground";
import Network3D from "../components/animations/Network3D";
import CerberusLogo from "../components/common/CerberusLogo";
import TypingEffect from "../components/animations/TypingEffect";
import CountUp from "../components/ui/CountUp";
import AboutSection from "../components/landing/AboutSection";
import ArchitectureSection from "../components/landing/ArchitectureSection";
import Footer from "../components/layout/Footer";

const capabilities = [
  { title: "AI-Powered Penetration Testing", description: "Automated security assessments guided by intelligent AI agents that adapt to your organization's unique infrastructure.", icon: "🎯" },
  { title: "Automated OSINT Collection", description: "Comprehensive open-source intelligence gathering from DNS records, certificate transparency, breach databases, and more.", icon: "🔍" },
  { title: "Intelligent Attack Path Generation", description: "AI constructs attack graphs to identify the most probable and impactful attack scenarios against your infrastructure.", icon: "🗺️" },
  { title: "Comprehensive Risk Analysis", description: "Technical vulnerabilities translated into measurable business risk with contextual severity analysis.", icon: "📊" },
  { title: "Professional Report Generation", description: "Industry-standard penetration testing reports with executive summaries, detailed findings, and remediation roadmaps.", icon: "📄" },
  { title: "Blue Team Defense Architecture", description: "Three-tier security system combining WAF, AI behavioral analysis, and generative AI for adaptive threat prevention.", icon: "🛡️" },
];

const stats = [
  { label: "Security Assessments", value: 1247 },
  { label: "Protected Organizations", value: 389 },
  { label: "Vulnerabilities Discovered", value: 15632 },
  { label: "Reports Generated", value: 892 },
];

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen relative overflow-hidden">
      <ParticleBackground />

      {/* ─── Hero Section ────────────────────── */}
      <section className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4">
        <div className="absolute inset-0 overflow-hidden">
          <Network3D />
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="text-center relative z-10"
        >
          <CerberusLogo size="lg" />

          <div className="mt-6 text-lg md:text-xl text-gray-300 max-w-2xl mx-auto leading-relaxed">
            <TypingEffect
              texts={[
                "Intelligent penetration testing powered by AI.",
                "Automated security assessments for your organization.",
                "AI-assisted cybersecurity analysis — all in one platform.",
              ]}
            />
          </div>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => navigate("/register")}
            className="btn-glow mt-10 text-lg"
          >
            Registration Started →
          </motion.button>
        </motion.div>

        {/* Scroll indicator */}
        <motion.div
          animate={{ y: [0, 10, 0] }}
          transition={{ repeat: Infinity, duration: 2 }}
          className="absolute bottom-10 text-cerberus-blue/50 z-10"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        </motion.div>
      </section>

      {/* ─── Capabilities Section ── */}
      <section className="relative z-10 py-24 px-4 max-w-7xl mx-auto">
        <motion.h2
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="text-3xl md:text-4xl font-bold text-center mb-16"
        >
          <span className="text-gradient">Platform Capabilities</span>
        </motion.h2>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {capabilities.map((cap, i) => (
            <motion.div
              key={cap.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="cyber-card group cursor-default"
            >
              <span className="text-4xl mb-4 block group-hover:scale-110 transition-transform">{cap.icon}</span>
              <h3 className="text-xl font-semibold text-white mb-2">{cap.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{cap.description}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ─── Stats Section ── */}
      <section className="relative z-10 py-24 px-4 bg-cerberus-gray-900/50">
        <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
          {stats.map((stat) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <CountUp target={stat.value} className="text-4xl md:text-5xl font-bold text-cerberus-blue glow-text" />
              <p className="mt-2 text-sm text-gray-400">{stat.label}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ─── About Section ── */}
      <AboutSection />

      {/* ─── Architecture Section ── */}
      <ArchitectureSection />

      {/* ─── Footer ── */}
      <Footer />
    </div>
  );
}
