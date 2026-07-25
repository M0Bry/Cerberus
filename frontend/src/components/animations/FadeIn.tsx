/** FadeIn — Fade in on mount / scroll. */
import { motion } from "framer-motion";
import { ReactNode } from "react";
export default function FadeIn({ children, delay = 0, className = "" }: { children: ReactNode; delay?: number; className?: string }) {
  return <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay, duration: 0.6 }} className={className}>{children}</motion.div>;
}
