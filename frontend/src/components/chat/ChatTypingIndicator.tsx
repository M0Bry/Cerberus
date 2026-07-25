/** ChatTypingIndicator — "AI is typing..." with animated dots. */
export default function ChatTypingIndicator() {
  return (
    <div className="flex justify-start mb-4">
      <div className="bg-cerberus-gray-800 border border-cerberus-gray-700 rounded-2xl px-5 py-3">
        <div className="flex items-center gap-2 mb-1"><span>🤖</span><span className="text-[10px] font-mono text-cerberus-blue">CERBERUS AI</span></div>
        <div className="flex gap-1">
          {[0, 0.15, 0.3].map((d, i) => <span key={i} className="w-2 h-2 bg-cerberus-blue rounded-full animate-bounce" style={{ animationDelay: `${d}s` }} />)}
        </div>
      </div>
    </div>
  );
}
