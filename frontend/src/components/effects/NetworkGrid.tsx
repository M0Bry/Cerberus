/**
 * NetworkGrid — ambient cyber background (fixed, z-index -1, behind the entire UI).
 * Ported from the new front-end's js/main.js (node network + cursor light + parallax grid).
 */
import { useEffect, useRef } from "react";

export default function NetworkGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const grid = gridRef.current;
    if (!canvas || !grid) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const DPR = Math.min(window.devicePixelRatio || 1, 1.75);
    let W = 0;
    let H = 0;
    let raf = 0;
    const nodes: Array<{
      x: number; y: number; vx: number; vy: number; s: number; red: boolean; ox: number; oy: number;
    }> = [];
    const mouse = { x: innerWidth / 2, y: innerHeight / 2 };

    const initNodes = () => {
      const n = Math.min(Math.floor((W * H) / 45000), 50);
      nodes.length = 0;
      for (let i = 0; i < n; i++) {
        nodes.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.12,
          vy: (Math.random() - 0.5) * 0.12,
          s: Math.random() * 1.6 + 1,
          red: Math.random() < 0.18,
          ox: 0,
          oy: 0,
        });
      }
    };

    const resize = () => {
      W = innerWidth;
      H = innerHeight;
      canvas.width = W * DPR;
      canvas.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      initNodes();
      if (reduced) draw(false);
    };

    const draw = (interactive: boolean) => {
      ctx.clearRect(0, 0, W, H);
      const R = 160;
      for (const n of nodes) {
        if (!reduced) {
          n.x += n.vx;
          n.y += n.vy;
          if (n.x < -10) n.x = W + 10;
          if (n.x > W + 10) n.x = -10;
          if (n.y < -10) n.y = H + 10;
          if (n.y > H + 10) n.y = -10;
        }
        n.ox = 0;
        n.oy = 0;
        if (interactive) {
          const dx = n.x - mouse.x;
          const dy = n.y - mouse.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < R * R) {
            const d = Math.sqrt(d2) || 1;
            const f = (1 - d / R) * 6;
            n.ox = (dx / d) * f;
            n.oy = (dy / d) * f;
          }
        }
      }
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const dx = a.x + a.ox - (b.x + b.ox);
          const dy = a.y + a.oy - (b.y + b.oy);
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 130) {
            ctx.strokeStyle = `rgba(157,20,29,${(0.07 * (1 - d / 130)).toFixed(3)})`;
            ctx.beginPath();
            ctx.moveTo(a.x + a.ox, a.y + a.oy);
            ctx.lineTo(b.x + b.ox, b.y + b.oy);
            ctx.stroke();
          }
        }
      }
      if (interactive) {
        for (const n of nodes) {
          const dx = n.x + n.ox - mouse.x;
          const dy = n.y + n.oy - mouse.y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 140) {
            ctx.strokeStyle = `rgba(242,242,242,${(0.06 * (1 - d / 140)).toFixed(3)})`;
            ctx.beginPath();
            ctx.moveTo(n.x + n.ox, n.y + n.oy);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.stroke();
          }
        }
      }
      for (const n of nodes) {
        ctx.fillStyle = n.red ? "rgba(157,20,29,.38)" : "rgba(242,242,242,.13)";
        ctx.fillRect(n.x + n.ox - n.s / 2, n.y + n.oy - n.s / 2, n.s, n.s);
      }
    };

    let gx = 0;
    let gy = 0;
    const loop = () => {
      if (!document.hidden) {
        draw(true);
        gx += ((mouse.x / W - 0.5) * -10 - gx) * 0.06;
        gy += ((mouse.y / H - 0.5) * -10 - gy) * 0.06;
        grid.style.transform = `translate(${gx}px,${gy}px)`;
      }
      raf = requestAnimationFrame(loop);
    };

    const onMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };

    addEventListener("resize", resize, { passive: true });
    addEventListener("mousemove", onMouseMove, { passive: true });
    resize();
    if (reduced) {
      grid.style.transform = "none";
      draw(false);
    } else {
      loop();
    }

    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("resize", resize);
      removeEventListener("mousemove", onMouseMove);
      grid.style.transform = "";
    };
  }, []);

  return (
    <>
      <div ref={gridRef} className="cyber-grid" aria-hidden="true" />
      <canvas ref={canvasRef} id="net-canvas" aria-hidden="true" />
    </>
  );
}
