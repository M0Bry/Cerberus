/** FeaturesSection — Feature cards (hover glow + lift + gradient). */
import { motion } from "framer-motion";
const features = [
  { icon: "🎯", title: "AI-Powered Penetration Testing", desc: "Automated security assessments guided by intelligent AI agents." },
  { icon: "🔍", title: "Automated OSINT Collection", desc: "Intelligence from DNS, certificates, breaches, and more." },
  { icon: "🗺️", title: "Intelligent Attack Paths", desc: "AI constructs attack graphs for maximum impact scenarios." },
  { icon: "📊", title: "Comprehensive Risk Analysis", desc: "Technical vulns translated into measurable business risk." },
  { icon: "📄", title: "Professional Reports", desc: "Executive summaries, findings, evidence, remediation roadmaps." },
  { icon: "🛡️", title: "Blue Team Defense", desc: "Three-tier security: WAF + AI behavioral + generative AI." },
];
export default function FeaturesSection() {
  return (
    <section className="py-24 px-4 max-w-7xl mx-auto">
      <h2 className="text-3xl font-bold text-center mb-16"><span className="text-gradient">Platform Capabilities</span></h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((f, i) => (
          <motion.div key={f.title} initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.1 }} className="cyber-card group">
            <span className="text-4xl mb-4 block group-hover:scale-110 transition-transform">{f.icon}</span>
            <h3 className="text-xl font-semibold text-white mb-2">{f.title}</h3>
            <p className="text-gray-400 text-sm">{f.desc}</p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
