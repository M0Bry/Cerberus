/**
 * API Configuration.
 */
export const API_CONFIG = {
  baseUrl: import.meta.env.VITE_API_URL || "/api/v1",
  timeout: 30000,
  retryAttempts: 2,
};
