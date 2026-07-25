/** StatsSection — Animated counters (assessments, orgs, vulns, reports). */
import { motion } from "framer-motion";
import CountUp from "../ui/CountUp";
const stats = [{ label: "Security Assessments", value: 1247 }, { label: "Protected Organizations", value: 389 }, { label: "Vulnerabilities Discovered", value: 15632 }, { label: "Reports Generated", value: 892 }];
export default function StatsSection() {
  return (
    <section className="py-24 px-4 bg-cerberus-gray-900/50">
      <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
        {stats.map((s) => (
          <motion.div key={s.label} initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} className="text-center">
            <CountUp target={s.value} className="text-4xl md:text-5xl font-bold text-cerberus-blue glow-text" />
            <p className="mt-2 text-sm text-gray-400">{s.label}</p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
