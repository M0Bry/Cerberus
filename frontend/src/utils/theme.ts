/** Theme — Dark/Light mode + system preference detection. */
export function getSystemTheme(): "dark" | "light" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
export function applyTheme(theme: "dark" | "light" | "system") {
  const resolved = theme === "system" ? getSystemTheme() : theme;
  document.documentElement.setAttribute("data-theme", resolved);
  localStorage.setItem("cerberus-theme", theme);
}
