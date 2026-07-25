/**
 * AuthShell — Exact auth card shell from the reference design.
 */
import { ReactNode } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import ParticleBackground from "../common/ParticleBackground";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface AuthLayoutProps {
  children: ReactNode;
  width?: number;
}

export default function AuthLayout({ children, width = 460 }: AuthLayoutProps) {
  return (
    <div
      style={{
        background: "#03060c",
        color: "#e8edf7",
        minHeight: "100vh",
        fontFamily: MONO,
        position: "relative",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <ParticleBackground />
      <Navbar />
      <div
        style={{
          position: "relative",
          zIndex: 1,
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "48px 24px",
        }}
      >
        <div
          className="fade-up"
          style={{
            width: "100%",
            maxWidth: width,
            background: "#0a101c",
            border: "1px solid #152238",
            borderRadius: 18,
            padding: "36px 34px",
            boxShadow: "0 30px 80px -40px rgba(0,0,20,0.8)",
          }}
        >
          {children}
        </div>
      </div>
      <Footer />
    </div>
  );
}
