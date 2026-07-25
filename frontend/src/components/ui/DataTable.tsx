/**
 * DataTable — Table matching the exact reference design.
 */
import { ReactNode } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface Column<T> {
  key: string;
  label: string;
  render?: (item: T) => ReactNode;
  sortable?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  pageSize?: number;
  emptyMessage?: string;
  onRowClick?: (item: T) => void;
}

export default function DataTable<T extends Record<string, any>>({
  columns, data, emptyMessage = "No data available", onRowClick,
}: DataTableProps<T>) {
  if (!data.length) {
    return (
      <div style={{ border: "1px solid #152238", borderRadius: 12, padding: "48px 20px", textAlign: "center" }}>
        <p style={{ color: "#5b6a86", fontFamily: MONO, fontSize: 13 }}>{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div style={{ border: "1px solid #152238", borderRadius: 12, overflow: "hidden" }}>
      {/* Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${columns.length}, 1fr)`,
          padding: "12px 20px",
          background: "rgba(47,125,250,0.06)",
          fontSize: 11,
          color: "#5b6a86",
          fontFamily: MONO,
        }}
      >
        {columns.map((col) => (
          <span key={col.key}>{col.label}</span>
        ))}
      </div>
      {/* Rows */}
      {data.map((item, i) => (
        <div
          key={i}
          onClick={() => onRowClick?.(item)}
          style={{
            display: "grid",
            gridTemplateColumns: `repeat(${columns.length}, 1fr)`,
            padding: "14px 20px",
            fontSize: 12.5,
            borderTop: "1px solid #152238",
            alignItems: "center",
            cursor: onRowClick ? "pointer" : "default",
            transition: "background 0.2s",
            fontFamily: MONO,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(47,125,250,0.04)")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          {columns.map((col) => (
            <span key={col.key} style={{ color: col.key === "status" ? "#22d3ee" : "#e8edf7" }}>
              {col.render ? col.render(item) : item[col.key]}
            </span>
          ))}
        </div>
      ))}
    </div>
  );
}
