/**
 * AboutSection — Site purpose, target audience, how it works (PDF Page 2).
 * "this page contains information about our website that appears when the user scrolls down,
 * such as the site's purpose, who can use the site, its target audience, and a brief overview of how the site works."
 */

import { motion } from "framer-motion";

const steps = [
  { num: "01", title: "Register & Verify", desc: "Create your account and verify your email to access the platform." },
  { num: "02", title: "AI-Guided Setup", desc: "Our AI agent collects your organization details and defines the testing scope." },
  { num: "03", title: "Automated Assessment", desc: "OSINT, attack planning, Red Team validation, and risk analysis — all automated." },
  { num: "04", title: "Professional Report", desc: "Receive a comprehensive PDF report with findings, evidence, and remediation roadmap." },
];

const audience = [
  { icon: "🏢", title: "Enterprises", desc: "Large organizations needing comprehensive security assessments." },
  { icon: "🏦", title: "Financial Institutions", desc: "Banks and fintech companies requiring PCI-DSS compliance." },
  { icon: "🏥", title: "Healthcare", desc: "Medical organizations needing HIPAA-compliant security testing." },
  { icon: "💻", title: "Tech Companies", desc: "Software companies testing web apps, APIs, and cloud infrastructure." },
];

export default function AboutSection() {
  return (
    <section className="py-24 px-4 max-w-7xl mx-auto">
      {/* How It Works */}
      <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
        <h2 className="text-3xl font-bold text-center mb-4">
          <span className="text-gradient">How It Works</span>
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-12">
          From registration to report in four simple steps. Every phase is guided by AI.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-24">
        {steps.map((step, i) => (
          <motion.div
            key={step.num}
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.15 }}
            className="cyber-card text-center relative"
          >
            <span className="text-5xl font-bold text-cerberus-blue/10 absolute top-4 right-4">{step.num}</span>
            <h3 className="text-lg font-semibold text-white mb-2 relative z-10">{step.title}</h3>
            <p className="text-sm text-gray-400 relative z-10">{step.desc}</p>
          </motion.div>
        ))}
      </div>

      {/* Who Can Use */}
      <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
        <h2 className="text-3xl font-bold text-center mb-4">
          <span className="text-gradient">Who Can Use Cerberus AI</span>
        </h2>
        <p className="text-gray-400 text-center max-w-2xl mx-auto mb-12">
          Designed for organizations of all sizes that take cybersecurity seriously.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {audience.map((a, i) => (
          <motion.div
            key={a.title}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1 }}
            className="cyber-card text-center"
          >
            <span className="text-3xl mb-3 block">{a.icon}</span>
            <h3 className="text-white font-semibold mb-1">{a.title}</h3>
            <p className="text-sm text-gray-400">{a.desc}</p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
