/** PulseRing — Pulsing ring animation for status indicators. */
export default function PulseRing({ color = "cerberus-blue", size = "w-4 h-4" }: { color?: string; size?: string }) {
  return (
    <span className="relative flex items-center justify-center">
      <span className={`absolute ${size} rounded-full bg-${color}/30 animate-ping`} />
      <span className={`relative ${size} rounded-full bg-${color}`} />
    </span>
  );
}
