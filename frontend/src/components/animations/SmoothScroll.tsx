/** SmoothScroll — Smooth scroll wrapper. */
import { ReactNode } from "react";
export default function SmoothScroll({ children }: { children: ReactNode }) {
  return <div className="scroll-smooth">{children}</div>;
}
