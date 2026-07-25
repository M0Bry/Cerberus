/**
 * ChartCard — Chart card matching the reference design.
 */
import { ReactNode } from "react";
import Card from "./Card";

const DISPLAY = "'Orbitron', 'Share Tech Mono', sans-serif";

interface ChartCardProps {
  title: string;
  children: ReactNode;
  style?: React.CSSProperties;
}

export default function ChartCard({ title, children, style }: ChartCardProps) {
  return (
    <Card style={style}>
      <h3 style={{ fontFamily: DISPLAY, fontSize: 13, fontWeight: 700, color: "#8493ac", letterSpacing: 1, marginBottom: 16, textTransform: "uppercase" }}>
        {title}
      </h3>
      {children}
    </Card>
  );
}
