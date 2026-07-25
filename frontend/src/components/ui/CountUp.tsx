/**
 * CountUp — Animated counter matching the reference design.
 */
import { useEffect, useRef, useState } from "react";

interface CountUpProps {
  target: number;
  duration?: number;
  suffix?: string;
  className?: string;
  style?: React.CSSProperties;
}

export default function CountUp({ target, duration = 2000, suffix = "", style }: CountUpProps) {
  const [value, setValue] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          let startTime: number | null = null;
          function step(ts: number) {
            if (startTime === null) startTime = ts;
            const progress = Math.min((ts - startTime) / duration, 1);
            setValue(Math.floor(progress * target));
            if (progress < 1) requestAnimationFrame(step);
          }
          requestAnimationFrame(step);
        }
      },
      { threshold: 0.3 }
    );
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [target, duration]);

  return (
    <span ref={ref} className="stat-num" style={style}>
      {value.toLocaleString()}{suffix}
    </span>
  );
}
