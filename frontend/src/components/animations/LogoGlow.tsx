/** LogoGlow — Cerberus logo with pulsing glow. */
export default function LogoGlow({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  const s = { sm: "text-3xl", md: "text-5xl", lg: "text-7xl" }[size];
  return <div className={`${s} animate-glow-pulse glow-text`}>🛡️</div>;
}
