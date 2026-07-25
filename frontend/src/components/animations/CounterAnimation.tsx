/** CounterAnimation — Animated counting for stats section. */
import CountUp from "../ui/CountUp";
export default function CounterAnimation({ target, label, className = "" }: { target: number; label: string; className?: string }) {
  return (
    <div className={`text-center ${className}`}>
      <CountUp target={target} className="text-4xl md:text-5xl font-bold text-cerberus-blue glow-text" />
      <p className="mt-2 text-sm text-gray-400">{label}</p>
    </div>
  );
}
