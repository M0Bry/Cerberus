/** CrossoverGradient — Moving gradient hover for buttons/cards. */
import { ReactNode } from "react";
export default function CrossoverGradient({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`relative overflow-hidden group ${className}`}>{children}<div className="absolute inset-0 bg-gradient-to-r from-transparent via-cerberus-blue/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" /></div>;
}
