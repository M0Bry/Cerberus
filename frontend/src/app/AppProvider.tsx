/**
 * AppProvider — Composes all providers.
 */
import { ReactNode } from "react";
import { BrowserRouter } from "react-router-dom";
import { QueryProvider } from "./QueryProvider";
import { ThemeProvider } from "../contexts/ThemeContext";
import { ToastProvider } from "../components/ui/Toast";

export function AppProvider({ children }: { children: ReactNode }) {
  return (
    <QueryProvider>
      <BrowserRouter>
        <ThemeProvider>
          <ToastProvider>
            {children}
          </ToastProvider>
        </ThemeProvider>
      </BrowserRouter>
    </QueryProvider>
  );
}
