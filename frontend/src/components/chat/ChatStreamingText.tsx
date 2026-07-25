/** ChatStreamingText — Streaming text animation (SSE chunks). */
import { useState, useEffect } from "react";
export default function ChatStreamingText({ text, speed = 20 }: { text: string; speed?: number }) {
  const [displayed, setDisplayed] = useState("");
  useEffect(() => {
    let i = 0; setDisplayed("");
    const t = setInterval(() => { if (i < text.length) { setDisplayed(text.slice(0, i + 1)); i++; } else clearInterval(t); }, speed);
    return () => clearInterval(t);
  }, [text, speed]);
  return <span>{displayed}<span className="animate-pulse">|</span></span>;
}
