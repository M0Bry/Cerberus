/**
 * Skeleton — Skeleton loader matching the reference design.
 */
interface SkeletonProps { className?: string; lines?: number; height?: number; }
export default function Skeleton({ lines = 1, height = 16 }: SkeletonProps) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          style={{
            height,
            background: "rgba(255,255,255,0.06)",
            borderRadius: 6,
            width: i === lines - 1 ? "70%" : "100%",
            animation: "float 2s ease-in-out infinite",
          }}
        />
      ))}
    </div>
  );
}
