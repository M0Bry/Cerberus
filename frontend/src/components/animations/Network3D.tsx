/**
 * Network3D — Three-dimensional network visualization for hero section.
 * Creates an interactive 3D-like network of connected nodes using canvas.
 */

import { useEffect, useRef } from "react";

interface Node {
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  radius: number;
  opacity: number;
}

export default function Network3D() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.parentElement?.clientWidth || 800;
      canvas.height = canvas.parentElement?.clientHeight || 600;
    };
    resize();
    window.addEventListener("resize", resize);

    // Create 3D nodes
    const nodes: Node[] = [];
    for (let i = 0; i < 60; i++) {
      nodes.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        z: Math.random() * 300,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        radius: Math.random() * 3 + 1,
        opacity: Math.random() * 0.5 + 0.2,
      });
    }

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Sort by z-depth for pseudo-3D
      nodes.sort((a, b) => b.z - a.z);

      nodes.forEach((node, i) => {
        // Move
        node.x += node.vx;
        node.y += node.vy;

        // Wrap
        if (node.x < 0) node.x = canvas.width;
        if (node.x > canvas.width) node.x = 0;
        if (node.y < 0) node.y = canvas.height;
        if (node.y > canvas.height) node.y = 0;

        // Pseudo-3D scale based on z
        const scale = 1 - node.z / 400;
        const r = node.radius * scale;
        const alpha = node.opacity * scale;

        // Draw node
        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 212, 255, ${alpha})`;
        ctx.fill();

        // Draw glow
        const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 4);
        gradient.addColorStop(0, `rgba(0, 212, 255, ${alpha * 0.3})`);
        gradient.addColorStop(1, "rgba(0, 212, 255, 0)");
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 4, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw connections
        nodes.forEach((node2, j) => {
          if (i === j) return;
          const dx = node.x - node2.x;
          const dy = node.y - node2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 200 * scale) {
            ctx.beginPath();
            ctx.moveTo(node.x, node.y);
            ctx.lineTo(node2.x, node2.y);
            ctx.strokeStyle = `rgba(0, 212, 255, ${0.08 * scale * (1 - dist / 200)})`;
            ctx.lineWidth = 0.5 * scale;
            ctx.stroke();
          }
        });
      });

      requestAnimationFrame(animate);
    };

    const animId = requestAnimationFrame(animate);
    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none opacity-60"
    />
  );
}
