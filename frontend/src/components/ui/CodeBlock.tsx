/**
 * CodeBlock — Code block matching the reference design.
 */
const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface CodeBlockProps {
  code: string;
  title?: string;
}

export default function CodeBlock({ code, title }: CodeBlockProps) {
  return (
    <div style={{ borderRadius: 10, overflow: "hidden", border: "1px solid #152238" }}>
      {title && (
        <div style={{
          padding: "8px 14px",
          background: "rgba(47,125,250,0.06)",
          borderBottom: "1px solid #152238",
          fontSize: 11,
          color: "#8493ac",
          fontFamily: MONO,
        }}>
          {title}
        </div>
      )}
      <pre style={{
        padding: "14px 16px",
        background: "#040810",
        fontSize: 12.5,
        color: "#34e0a1",
        fontFamily: MONO,
        overflowX: "auto",
        margin: 0,
        lineHeight: 1.7,
      }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}
