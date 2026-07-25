/** ScrollReveal — Reveal on scroll (Intersection Observer). */
import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { ReactNode } from "react";
export default function ScrollReveal({ children, className = "" }: { children: ReactNode; className?: string }) {
  const ref = useRef(null);
  const isInView = useInView(ref, { once: true });
  return <motion.div ref={ref} initial={{ opacity: 0, y: 20 }} animate={isInView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.6 }} className={className}>{children}</motion.div>;
}
