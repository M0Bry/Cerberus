/** ChatInput — Input with send button + file attach + suggestions. */
import { useState, FormEvent } from "react";
interface ChatInputProps { onSend: (msg: string) => void; disabled?: boolean; placeholder?: string; }
export default function ChatInput({ onSend, disabled, placeholder = "Type your response..." }: ChatInputProps) {
  const [value, setValue] = useState("");
  const handleSubmit = (e: FormEvent) => { e.preventDefault(); if (value.trim()) { onSend(value.trim()); setValue(""); } };
  return (
    <form onSubmit={handleSubmit} className="max-w-4xl mx-auto flex gap-3">
      <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={placeholder} className="cyber-input flex-1" disabled={disabled} />
      <button type="submit" disabled={!value.trim() || disabled} className="btn-glow disabled:opacity-50">Send</button>
    </form>
  );
}
