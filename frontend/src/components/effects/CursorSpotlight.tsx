/**
 * CursorSpotlight — red-tinted radial that eases after the pointer inside the hero.
 * Ported from the new front-end's js/main.js. Static & hidden under prefers-reduced-motion.
 */
import { useEffect, useRef } from "react";

export default function CursorSpotlight({ className = "hero-spot" }: { className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const spot = ref.current;
    const hero = document.querySelector(".hero");
    if (!spot || !hero) return;
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      spot.style.display = "none";
      return;
    }

    const r = () => hero.getBoundingClientRect();
    let tx = innerWidth * 0.7;
    let ty = innerHeight * 0.4;
    let x = tx;
    let y = ty;
    let raf = 0;

    const onMouseMove = (e: MouseEvent) => {
      tx = e.clientX;
      ty = e.clientY;
    };
    const loop = () => {
      if (!document.hidden) {
        x += (tx - x) * 0.07;
        y += (ty - y) * 0.07;
        const hr = r();
        spot.style.transform = `translate(${x - hr.left - 360}px,${y - hr.top - 360}px)`;
      }
      raf = requestAnimationFrame(loop);
    };

    addEventListener("mousemove", onMouseMove, { passive: true });
    loop();
    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("mousemove", onMouseMove);
      spot.style.transform = "";
    };
  }, []);

  return <div ref={ref} className={className} aria-hidden="true" />;
}
