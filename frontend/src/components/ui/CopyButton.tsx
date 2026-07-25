/**
 * CopyButton — Copy to clipboard matching the reference design.
 */
import { useState } from "react";

const MONO = "'Share Tech Mono', 'Courier New', monospace";

export default function CopyButton({ text, style }: { text: string; style?: React.CSSProperties }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      style={{
        fontSize: 11,
        color: copied ? "#34e0a1" : "#8493ac",
        background: "none",
        border: "none",
        cursor: "pointer",
        fontFamily: MONO,
        transition: "color 0.2s",
        ...style,
      }}
    >
      {copied ? "✓ Copied!" : "📋 Copy"}
    </button>
  );
}
