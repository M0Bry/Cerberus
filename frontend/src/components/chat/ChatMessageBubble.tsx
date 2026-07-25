/** ChatMessageBubble — Message bubble (user vs AI vs system). */
import { ChatMessage } from "../../types";
export default function ChatMessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"} mb-4`}>
      <div className={`max-w-[80%] rounded-2xl px-5 py-3 ${isUser ? "bg-cerberus-blue/20 border border-cerberus-blue/30 text-white" : "bg-cerberus-gray-800 border border-cerberus-gray-700 text-gray-200"}`}>
        {!isUser && <div className="flex items-center gap-2 mb-2"><span>🤖</span><span className="text-[10px] font-mono text-cerberus-blue">CERBERUS AI</span></div>}
        <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
        <p className="text-[10px] text-gray-500 mt-2 text-right">{new Date(message.timestamp).toLocaleTimeString()}</p>
      </div>
    </div>
  );
}
