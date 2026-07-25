/**
 * WebSocketContext — WebSocket provider for real-time alerts.
 */
import { createContext, useContext, useEffect, useRef, useState, ReactNode } from "react";

interface WSMessage {
  type: string;
  payload: any;
}

interface WebSocketContextValue {
  connected: boolean;
  send: (msg: WSMessage) => void;
  lastMessage: WSMessage | null;
}

const WebSocketContext = createContext<WebSocketContextValue>({
  connected: false,
  send: () => {},
  lastMessage: null,
});

export function useWebSocket() {
  return useContext(WebSocketContext);
}

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);

  useEffect(() => {
    const wsUrl = import.meta.env.VITE_WS_URL || "ws://localhost:8000/api/v1";
    const token = localStorage.getItem("access_token");
    if (!token) return;

    const ws = new WebSocket(`${wsUrl}/ws?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      try {
        setLastMessage(JSON.parse(e.data));
      } catch {}
    };

    return () => ws.close();
  }, []);

  const send = (msg: WSMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  };

  return (
    <WebSocketContext.Provider value={{ connected, send, lastMessage }}>
      {children}
    </WebSocketContext.Provider>
  );
}
