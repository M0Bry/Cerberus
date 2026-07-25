/**
 * Environment Configuration.
 */
export const ENV = {
  isDev: import.meta.env.DEV,
  isProd: import.meta.env.PROD,
  apiUrl: import.meta.env.VITE_API_URL || "/api/v1",
  wsUrl: import.meta.env.VITE_WS_URL || "ws://localhost:8000/api/v1",
  appName: import.meta.env.VITE_APP_NAME || "Cerberus AI",
};
