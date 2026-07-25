/** HeroSection — Hero (3D network + particles + logo glow + CTA). */
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import Network3D from "../animations/Network3D";
import CerberusLogo from "../common/CerberusLogo";
import TypingEffect from "../animations/TypingEffect";

export default function HeroSection() {
  const navigate = useNavigate();

  return (
    <section className="relative flex flex-col items-center justify-center min-h-screen px-4">
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
        <div className="mt-6 text-lg md:text-xl text-gray-300 max-w-2xl mx-auto">
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
          Get Started →
        </motion.button>
      </motion.div>
    </section>
  );
}
