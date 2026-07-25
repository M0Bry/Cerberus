/** StaggerContainer — Stagger children animations. */
import { motion } from "framer-motion";
import { ReactNode } from "react";
export default function StaggerContainer({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={{ visible: { transition: { staggerChildren: 0.1 } } }} className={className}>{children}</motion.div>;
}
