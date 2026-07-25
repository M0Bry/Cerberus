import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "./contexts/ThemeContext";
import { ToastProvider } from "./components/ui/Toast";
import { WebSocketProvider } from "./contexts/WebSocketContext";
import AppRouter from "./router/AppRouter";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5 * 60 * 1000, retry: 2, refetchOnWindowFocus: false },
    mutations: { retry: 1 },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeProvider>
          <WebSocketProvider>
            <ToastProvider>
              <AppRouter />
            </ToastProvider>
          </WebSocketProvider>
        </ThemeProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
