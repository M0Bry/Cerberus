/**
 * CountUpValue — animated counter (new design), IntersectionObserver-triggered.
 * Ported from the new front-end's js/main.js (countUp + countObs).
 */
import { useEffect, useRef, useState } from "react";

interface CountUpValueProps {
  target: number;
  prefix?: string;
  suffix?: string;
  className?: string;
  /** Initial text before the animation starts (matches the mock markup). */
  initial?: string;
}

export default function CountUpValue({ target, prefix = "", suffix = "", className, initial }: CountUpValueProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [display, setDisplay] = useState(initial ?? "0");
  const done = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      setDisplay(prefix + target.toLocaleString("en-US") + suffix);
      return;
    }

    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting && !done.current) {
            done.current = true;
            const duration = 1700;
            const start = performance.now();
            const frame = (now: number) => {
              const p = Math.min((now - start) / duration, 1);
              const eased = 1 - Math.pow(1 - p, 3);
              setDisplay(prefix + Math.round(eased * target).toLocaleString("en-US") + suffix);
              if (p < 1) requestAnimationFrame(frame);
            };
            requestAnimationFrame(frame);
            obs.unobserve(e.target);
          }
        });
      },
      { threshold: 0.5 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [prefix, suffix, target]);

  return (
    <div ref={ref} className={className} data-target={target}>
      {display}
    </div>
  );
}
