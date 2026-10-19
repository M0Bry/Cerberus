/**
 * AuthEmbers — rising ember sparks (fire-like) behind the auth pages.
 * Ported from the new front-end's js/app.js.
 */
import { useEffect, useRef } from "react";

export default function AuthEmbers({ canvasId = "authEmbers" }: { canvasId?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const ctx = cv.getContext("2d");
    if (!ctx) return;

    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DPR = Math.min(window.devicePixelRatio || 1, 1.75);
    const rnd = (a: number, b: number) => a + Math.random() * (b - a);

    interface P { x: number; r: number; vy: number; drift: number; a: number; vanishY: number; fade: number; y: number; }
    let W = 0;
    let H = 0;
    let ps: P[] = [];
    let raf = 0;

    const spawn = (p: P, init: boolean): P => {
      p.x = rnd(0, W);
      p.r = rnd(1.6, 3.1);
      p.vy = rnd(110, 240);
      p.drift = rnd(-20, 20);
      p.a = rnd(0.55, 0.95);
      p.vanishY = rnd(H * 0.12, H * 0.7);
      p.fade = rnd(40, 90);
      p.y = init ? rnd(p.vanishY, H + 20) : H + rnd(5, 40);
      return p;
    };

    const build = () => {
      W = innerWidth;
      H = innerHeight;
      cv.width = Math.round(W * DPR);
      cv.height = Math.round(H * DPR);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      ps = Array.from({ length: Math.min(12, Math.round(W / 130)) }, () => spawn({} as P, true));
    };

    const drawStatic = () => {
      ctx.clearRect(0, 0, W, H);
      for (const p of ps) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, 7);
        ctx.fillStyle = `rgba(211,44,34,${p.a.toFixed(3)})`;
        ctx.fill();
      }
    };

    if (reduce) {
      build();
      drawStatic();
      const onResize = () => {
        build();
        drawStatic();
      };
      addEventListener("resize", onResize);
      return () => removeEventListener("resize", onResize);
    }

    addEventListener("resize", build);
    build();

    let last = performance.now();
    const frame = (t: number) => {
      const dt = Math.min(50, t - last);
      last = t;
      if (!document.hidden) {
        ctx.clearRect(0, 0, W, H);
        for (const p of ps) {
          p.y -= (p.vy * dt) / 1000;
          p.x += (p.drift * dt) / 1000;
          if (p.y < p.vanishY) {
            spawn(p, false);
            continue;
          }
          const env = Math.max(0, Math.min(1, Math.min((H + 10 - p.y) / p.fade, (p.y - p.vanishY) / (p.fade * 1.4))));
          const a = p.a * env;
          if (a <= 0) continue;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r, 0, 7);
          ctx.fillStyle = `rgba(211,44,34,${a.toFixed(3)})`;
          ctx.fill();
        }
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("resize", build);
    };
  }, [canvasId]);

  return <canvas ref={canvasRef} id={canvasId} aria-hidden="true" />;
}
