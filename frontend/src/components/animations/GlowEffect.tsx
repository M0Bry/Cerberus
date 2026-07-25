/** GlowEffect — Blue glow effect on hover. */
import { ReactNode } from "react";
export default function GlowEffect({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`transition-all duration-300 hover:shadow-lg hover:shadow-cerberus-blue/20 ${className}`}>{children}</div>;
}
