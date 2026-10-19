/**
 * HeroRain — Matrix-style "breach rain" of glyphs inside the hero section.
 * Faithful port of the new front-end's js/main.js (hero breach-rain block):
 * streams fade in at the top, drift down, VANISH at a random point between
 * 30–80% of the hero height, and respawn from the top with a 0–500ms delay.
 * Head glyph is brightest (6% chance warm-white), tail dims out; glyphs
 * re-randomize every 90–320ms (mutation). Static faint scatter under
 * prefers-reduced-motion. Paused when the hero is offscreen / tab hidden.
 */
import { useEffect, useRef } from "react";

const GLYPHS = "0123456789ABCDEF#$%&@!*+=<>/\\|;:^~";

export default function HeroRain({ canvasId = "heroRain", selector = ".hero" }: { canvasId?: string; selector?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    const hero = document.querySelector(selector);
    if (!cv || !hero) return;
    const ctx = cv.getContext("2d");
    if (!ctx) return;

    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DPR = Math.min(window.devicePixelRatio || 1, 1.75);
    const rnd = (a: number, b: number) => a + Math.random() * (b - a);
    const glyph = () => GLYPHS[(Math.random() * GLYPHS.length) | 0];

    interface Stream {
      col: number;
      x: number;
      size: number;
      speed: number;
      len: number;
      gap: number;
      chars: string[];
      vanish: number;
      fade: number;
      a: number;
      white: boolean;
      delay: number;
      y: number;
      mut: number;
    }

    let W = 0;
    let H = 0;
    let colW = 0;
    let streams: Stream[] = [];
    let inView = true;
    let raf = 0;
    let ro: IntersectionObserver | null = null;

    const spawn = (s: Stream, delay: boolean): Stream => {
      const j = colW || W / 100;
      s.x = Math.min(W - 8, Math.max(8, (s.col + 0.5) * j + rnd(-j * 0.18, j * 0.18)));
      s.size = Math.round(rnd(11, 17));
      s.speed = rnd(70, 170); // px per second
      s.len = 4 + ((Math.random() * 6) | 0);
      s.gap = s.size * 2.2;
      s.chars = Array.from({ length: s.len }, glyph);
      s.vanish = rnd(H * 0.3, H * 0.8); // random vanish point, 30–80% down
      s.fade = rnd(30, 60);
      s.a = rnd(0.25, 0.55);
      s.white = Math.random() < 0.06;
      s.delay = delay ? rnd(0, 500) : 0;
      s.y = -s.len * s.gap - rnd(0, 80);
      s.mut = 0;
      return s;
    };

    const build = () => {
      const r = hero.getBoundingClientRect();
      W = r.width;
      H = r.height;
      cv.width = Math.round(W * DPR);
      cv.height = Math.round(H * DPR);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      const n = Math.min(30, Math.round(W / 52));
      colW = W / n;
      streams = Array.from({ length: n }, (_, i) => {
        const s = spawn({ col: i, x: 0, size: 0, speed: 0, len: 0, gap: 0, chars: [], vanish: 0, fade: 0, a: 0, white: false, delay: 0, y: 0, mut: 0 }, false);
        s.y = rnd(-s.len * s.gap, H * 0.8);
        return s;
      });
    };

    const clipY = () => {
      const nav = document.querySelector(".navbar");
      if (!nav) return 0;
      return Math.max(0, Math.min(H, nav.getBoundingClientRect().bottom - hero.getBoundingClientRect().top));
    };

    const drawStatic = () => {
      ctx.clearRect(0, 0, W, H);
      const cy = clipY();
      ctx.save();
      ctx.beginPath();
      ctx.rect(0, cy, W, H - cy);
      ctx.clip();
      ctx.font = "12px monospace";
      for (let i = 0; i < 110; i++) {
        ctx.fillStyle = `rgba(207,39,49,${rnd(0.12, 0.32).toFixed(3)})`;
        ctx.fillText(glyph(), rnd(0, W), rnd(cy + 12, H));
      }
      ctx.restore();
    };

    if (reduce) {
      build();
      drawStatic();
      let rt: number | undefined;
      const onResize = () => {
        window.clearTimeout(rt);
        rt = window.setTimeout(() => {
          build();
          drawStatic();
        }, 150);
      };
      addEventListener("resize", onResize, { passive: true });
      return () => {
        window.clearTimeout(rt);
        removeEventListener("resize", onResize);
      };
    }

    ro = new IntersectionObserver((en) => {
      inView = en[0].isIntersecting;
    }, { threshold: 0 });
    ro.observe(hero);
    let rt: number | undefined;
    const onResize = () => {
      window.clearTimeout(rt);
      rt = window.setTimeout(build, 150);
    };
    addEventListener("resize", onResize, { passive: true });
    build();

    let last = performance.now();
    const frame = (t: number) => {
      const dt = Math.min(50, t - last);
      last = t;
      if (!document.hidden && inView) {
        ctx.clearRect(0, 0, W, H);
        const cy = clipY();
        ctx.save();
        ctx.beginPath();
        ctx.rect(0, cy, W, H - cy);
        ctx.clip();
        ctx.textAlign = "center";
        for (const s of streams) {
          if (s.delay > 0) {
            s.delay -= dt;
            continue;
          }
          s.y += (s.speed * dt) / 1000;
          // Vanish at the random point (30–80% down) and respawn from the top.
          if (s.y > s.vanish) {
            spawn(s, true);
            continue;
          }
          // Glyph mutation — a random char re-rolls every 90–320ms.
          s.mut -= dt;
          if (s.mut <= 0) {
            s.chars[(Math.random() * s.len) | 0] = glyph();
            s.mut = rnd(90, 320);
          }
          // Envelope: fade in from the top edge, fade out approaching vanish.
          const env = Math.max(0, Math.min(1, Math.min(s.y / s.fade, (s.vanish - s.y) / (s.fade * 1.6))));
          if (env <= 0) continue;
          ctx.font = `${s.size}px monospace`;
          for (let i = 0; i < s.len; i++) {
            const y = s.y - i * s.gap;
            if (y < cy - s.gap || y > H + s.gap) continue;
            const a = s.a * env * (i === 0 ? 1 : (1 - i / s.len) * 0.85);
            ctx.fillStyle =
              s.white && i === 0
                ? `rgba(255,214,196,${Math.min(0.6, a * 1.15).toFixed(3)})`
                : `rgba(207,39,49,${Math.min(0.9, a).toFixed(3)})`;
            ctx.fillText(s.chars[i], s.x, y);
          }
        }
        ctx.restore();
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro?.disconnect();
      window.clearTimeout(rt);
      removeEventListener("resize", onResize);
    };
  }, [canvasId, selector]);

  return <canvas ref={canvasRef} id={canvasId} aria-hidden="true" />;
}
