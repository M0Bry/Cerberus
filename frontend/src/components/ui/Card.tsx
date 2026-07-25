/**
 * Card — Cyber card matching the exact reference design.
 */
import { ReactNode, HTMLAttributes } from "react";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  hoverable?: boolean;
  padding?: "sm" | "md" | "lg";
  bordered?: boolean;
}

const padMap = { sm: "14px 16px", md: "22px 20px", lg: "32px 28px" };

export default function Card({
  children, hoverable = true, padding = "md", bordered = true,
  style, className = "", ...props
}: CardProps) {
  return (
    <div
      className={`cyber-card ${className}`}
      style={{
        padding: padMap[padding],
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  );
}
