/**
 * TypingEffect — Typewriter animation for hero text.
 */

import { useState, useEffect } from "react";

interface TypingEffectProps {
  texts: string[];
  speed?: number;
  deleteSpeed?: number;
  pauseMs?: number;
  className?: string;
}

export default function TypingEffect({
  texts, speed = 80, deleteSpeed = 40, pauseMs = 2000, className = "",
}: TypingEffectProps) {
  const [textIndex, setTextIndex] = useState(0);
  const [charIndex, setCharIndex] = useState(0);
  const [isDeleting, setIsDeleting] = useState(false);
  const [displayed, setDisplayed] = useState("");

  useEffect(() => {
    const currentText = texts[textIndex];

    const timeout = setTimeout(() => {
      if (!isDeleting) {
        setDisplayed(currentText.slice(0, charIndex + 1));
        setCharIndex((c) => c + 1);
        if (charIndex + 1 === currentText.length) {
          setTimeout(() => setIsDeleting(true), pauseMs);
        }
      } else {
        setDisplayed(currentText.slice(0, charIndex - 1));
        setCharIndex((c) => c - 1);
        if (charIndex - 1 === 0) {
          setIsDeleting(false);
          setTextIndex((i) => (i + 1) % texts.length);
        }
      }
    }, isDeleting ? deleteSpeed : speed);

    return () => clearTimeout(timeout);
  }, [charIndex, isDeleting, textIndex, texts, speed, deleteSpeed, pauseMs]);

  return (
    <span className={className}>
      {displayed}
      <span className="animate-pulse text-cerberus-blue">|</span>
    </span>
  );
}
