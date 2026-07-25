/** SlideUp — Slide up on scroll. */
import { motion } from "framer-motion";
import { ReactNode } from "react";
export default function SlideUp({ children, delay = 0, className = "" }: { children: ReactNode; delay?: number; className?: string }) {
  return <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay, duration: 0.6 }} className={className}>{children}</motion.div>;
}
