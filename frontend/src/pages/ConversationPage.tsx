/**
 * Conversation Page — AI chat interface for engagement setup.
 *
 * The Cerberus AI agent guides the user through requirement gathering
 * via a professional conversational interface.
 */

import { useState, useRef, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { engagementService } from "../services/engagement";

/* ------------------------------------------------------------------ */
/*  Local types                                                        */
/* ------------------------------------------------------------------ */

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

interface AIResponse {
  ai_response: string;
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function ConversationPage() {
  const { id: engagementId } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Hello, I'm Cerberus AI. Before we begin the security assessment, I need to understand your organization, infrastructure, and security objectives. Together, we will define an authorized penetration testing engagement tailored specifically to your environment.\n\nLet's start — what type of organization are you operating?",
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Send message mutation
  const sendMessage = useMutation({
    mutationFn: (message: string): Promise<AIResponse> =>
      engagementService
        .sendMessage(engagementId!, message)
        .then((res: { data: AIResponse }) => res.data),
    onMutate: (message) => {
      setMessages((prev) => [
        ...prev,
        { role: "user", content: message, timestamp: new Date().toISOString() },
      ]);
      setInput("");
      setIsTyping(true);
    },
    onSuccess: (data) => {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.ai_response,
          timestamp: new Date().toISOString(),
        },
      ]);
      setIsTyping(false);
    },
    onError: () => {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "I apologize, but I'm experiencing a temporary issue. Please try again.",
          timestamp: new Date().toISOString(),
        },
      ]);
      setIsTyping(false);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || sendMessage.isPending) return;
    sendMessage.mutate(input.trim());
  };

  return (
    <div className="h-screen flex flex-col bg-cerberus-dark">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-cerberus-gray-700 bg-cerberus-gray-900/80 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🛡️</span>
          <div>
            <h1 className="font-bold text-white">Cerberus AI</h1>
            <span className="text-xs text-cerberus-blue font-mono">
              ENGAGEMENT SETUP
            </span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="status-badge bg-cerberus-blue/20 text-cerberus-blue border border-cerberus-blue/30">
            🟢 Online
          </span>
          <button
            onClick={() => navigate("/dashboard")}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            ← Back to Dashboard
          </button>
        </div>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-6 max-w-4xl mx-auto w-full space-y-4">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[80%] rounded-2xl px-5 py-3 ${
                msg.role === "user"
                  ? "bg-cerberus-blue/20 border border-cerberus-blue/30 text-white"
                  : "bg-cerberus-gray-800 border border-cerberus-gray-700 text-gray-200"
              }`}
            >
              {msg.role === "assistant" && (
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-sm">🤖</span>
                  <span className="text-xs font-mono text-cerberus-blue">
                    CERBERUS AI
                  </span>
                </div>
              )}
              <p className="text-sm leading-relaxed whitespace-pre-wrap">
                {msg.content}
              </p>
              <p className="text-[10px] text-gray-500 mt-2 text-right">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </p>
            </div>
          </div>
        ))}

        {/* Typing indicator */}
        {isTyping && (
          <div className="flex justify-start">
            <div className="bg-cerberus-gray-800 border border-cerberus-gray-700 rounded-2xl px-5 py-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm">🤖</span>
                <span className="text-xs font-mono text-cerberus-blue">
                  CERBERUS AI
                </span>
              </div>
              <div className="flex gap-1">
                <span className="w-2 h-2 bg-cerberus-blue rounded-full animate-bounce" />
                <span
                  className="w-2 h-2 bg-cerberus-blue rounded-full animate-bounce"
                  style={{ animationDelay: "0.15s" }}
                />
                <span
                  className="w-2 h-2 bg-cerberus-blue rounded-full animate-bounce"
                  style={{ animationDelay: "0.3s" }}
                />
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-cerberus-gray-700 bg-cerberus-gray-900/80 backdrop-blur-sm px-4 py-4">
        <form
          onSubmit={handleSubmit}
          className="max-w-4xl mx-auto flex gap-3"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your response..."
            className="cyber-input flex-1"
            disabled={sendMessage.isPending}
          />
          <button
            type="submit"
            disabled={!input.trim() || sendMessage.isPending}
            className="btn-glow disabled:opacity-50"
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
