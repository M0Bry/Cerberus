/**
 * ChatPage — Full AI chat interface using chatStore for state management.
 */

import { useRef, useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { engagementService } from "../services/engagement";
import { useChatStore } from "../stores/chatStore";

export default function ChatPage() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const navigate = useNavigate();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const { messages, isLoading, addMessage, setLoading } = useChatStore();

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Seed initial greeting if empty
  useEffect(() => {
    if (messages.length === 0) {
      addMessage({
        role: "assistant",
        content:
          "Hello, I'm Cerberus AI. Before we begin the security assessment, I need to understand your organization, infrastructure, and security objectives.\n\nLet's start — what type of organization are you operating?",
        timestamp: new Date().toISOString(),
      });
    }
  }, [messages.length, addMessage]);

  // Send message mutation
  const sendMutation = useMutation({
    mutationFn: (text: string): Promise<{ ai_response: string }> =>
      engagementService
        .sendMessage(engagementId || "new", text) // ← pass plain string, not object
        .then((res: { data: { ai_response: string } }) => res.data),
    onMutate: (text) => {
      addMessage({ role: "user", content: text, timestamp: new Date().toISOString() });
      setLoading(true);
    },
    onSuccess: (data) => {
      addMessage({
        role: "assistant",
        content: data.ai_response,
        timestamp: new Date().toISOString(),
      });
      setLoading(false);
    },
    onError: () => {
      addMessage({
        role: "assistant",
        content: "Temporary issue. Please try again.",
        timestamp: new Date().toISOString(),
      });
      setLoading(false);
    },
  });

  const suggestions = [
    "We're a fintech company with 500 employees",
    "Our main assets are web APIs and cloud infrastructure",
    "We need to test our external attack surface",
    "Production systems must not be disrupted",
  ];

  const [input, setInput] = useState("");

  const handleSend = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    sendMutation.mutate(trimmed);
    setInput("");
  };

  return (
    <div className="h-screen flex flex-col bg-cerberus-dark">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-cerberus-gray-700 bg-cerberus-gray-900/80 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <span className="text-xl">🛡️</span>
          <div>
            <h1 className="font-bold text-white text-sm">Cerberus AI</h1>
            <span className="text-[10px] text-cerberus-blue font-mono">ENGAGEMENT SETUP</span>
          </div>
        </div>
        <button onClick={() => navigate("/dashboard")} className="text-xs text-gray-400 hover:text-white">
          ← Dashboard
        </button>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-6 max-w-4xl mx-auto w-full space-y-4">
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[80%] rounded-2xl px-5 py-3 ${
                msg.role === "user"
                  ? "bg-cerberus-blue/20 border border-cerberus-blue/30 text-white"
                  : "bg-cerberus-gray-800 border border-cerberus-gray-700 text-gray-200"
              }`}
            >
              {msg.role === "assistant" && (
                <div className="flex items-center gap-2 mb-2">
                  <span>🤖</span>
                  <span className="text-[10px] font-mono text-cerberus-blue">CERBERUS AI</span>
                </div>
              )}
              <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>
            </div>
          </div>
        ))}

        {/* Loading indicator */}
        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-cerberus-gray-800 border border-cerberus-gray-700 rounded-2xl px-5 py-3">
              <div className="flex gap-1">
                {[0, 0.15, 0.3].map((delay, i) => (
                  <span
                    key={i}
                    className="w-2 h-2 bg-cerberus-blue rounded-full animate-bounce"
                    style={{ animationDelay: `${delay}s` }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggestions */}
      {messages.length <= 2 && (
        <div className="max-w-4xl mx-auto w-full px-4 pb-2 flex flex-wrap gap-2">
          {suggestions.map((s, i) => (
            <button
              key={i}
              onClick={() => handleSend(s)}
              className="px-3 py-1.5 text-xs bg-cerberus-gray-800 border border-cerberus-gray-600 rounded-full text-gray-400 hover:text-cerberus-blue hover:border-cerberus-blue transition-all"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="border-t border-cerberus-gray-700 bg-cerberus-gray-900/80 px-4 py-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend(input);
          }}
          className="max-w-4xl mx-auto flex gap-3"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type your response..."
            className="cyber-input flex-1"
            disabled={isLoading}
          />
          <button type="submit" disabled={!input.trim() || isLoading} className="btn-glow disabled:opacity-50">
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
