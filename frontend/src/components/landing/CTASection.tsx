/** CTASection — "Registration Started" button + final CTA. */
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
export default function CTASection() {
  const navigate = useNavigate();
  return (
    <section className="py-24 px-4 text-center">
      <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
        <h2 className="text-3xl font-bold text-white mb-4">Ready to Secure Your Organization?</h2>
        <p className="text-gray-400 max-w-xl mx-auto mb-8">Start your first AI-powered security assessment today. No cybersecurity expertise required.</p>
        <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} onClick={() => navigate("/register")} className="btn-glow text-lg">Registration Started →</motion.button>
      </motion.div>
    </section>
  );
}
