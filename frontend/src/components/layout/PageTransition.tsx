/** PageTransition — Animation wrapper for page transitions. */
import { ReactNode } from "react";
import { motion } from "framer-motion";

export default function PageTransition({ children }: { children: ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.3 }}>
      {children}
    </motion.div>
  );
}
