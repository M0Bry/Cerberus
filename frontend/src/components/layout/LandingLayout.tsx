/** LandingLayout — Full-width layout with transparent nav for landing page. */
import { ReactNode } from "react";
import Navbar from "./Navbar";

export default function LandingLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <main>{children}</main>
    </div>
  );
}
