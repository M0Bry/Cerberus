/**
 * ArchitectureSection — Unique architecture description (PDF Page 2).
 * "highlights the platform's unique architecture, explaining that Cerberus AI combines
 * Artificial Intelligence with professional penetration testing methodologies while maintaining
 * legal compliance and ethical hacking principles."
 */

import { motion } from "framer-motion";

const pillars = [
  {
    icon: "🤖",
    title: "AI-Driven Automation",
    desc: "Every phase of the penetration testing lifecycle is orchestrated by intelligent AI agents that adapt to your organization's unique infrastructure.",
  },
  {
    icon: "⚖️",
    title: "Legal Compliance",
    desc: "Every engagement requires digitally signed Rules of Engagement. All activities are authorized, documented, and non-destructive.",
  },
  {
    icon: "🔬",
    title: "Evidence-Based Results",
    desc: "Every finding is supported by verifiable technical evidence — screenshots, logs, PoC results — cryptographically signed and timestamped.",
  },
  {
    icon: "🛡️",
    title: "Defense-in-Depth",
    desc: "Three-tier security architecture combining WAF, AI behavioral analysis, and generative AI for adaptive threat prevention.",
  },
];

export default function ArchitectureSection() {
  return (
    <section className="py-24 px-4 bg-cerberus-gray-900/50">
      <div className="max-w-7xl mx-auto">
        <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
          <h2 className="text-3xl font-bold text-center mb-4">
            <span className="text-gradient">Unique Architecture</span>
          </h2>
          <p className="text-gray-400 text-center max-w-3xl mx-auto mb-16">
            Cerberus AI combines Artificial Intelligence with professional penetration testing
            methodologies while maintaining legal compliance and ethical hacking principles.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {pillars.map((p, i) => (
            <motion.div
              key={p.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 }}
              className="text-center"
            >
              <span className="text-4xl mb-4 block">{p.icon}</span>
              <h3 className="text-lg font-semibold text-white mb-2">{p.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{p.desc}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
