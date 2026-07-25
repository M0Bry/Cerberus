/**
 * ThemeContext — Theme provider matching the reference design.
 */
import { createContext, useContext, ReactNode } from "react";

interface ThemeContextValue {
  theme: "dark";
}

const ThemeContext = createContext<ThemeContextValue>({ theme: "dark" });

export function useTheme() {
  return useContext(ThemeContext);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  return (
    <ThemeContext.Provider value={{ theme: "dark" }}>
      {children}
    </ThemeContext.Provider>
  );
}
