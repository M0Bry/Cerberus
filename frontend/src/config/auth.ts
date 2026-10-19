/**
 * Auth Configuration.
 */
export const AUTH_CONFIG = {
  tokenKey: "access_token",
  refreshTokenKey: "refresh_token",
  rememberKey: "cerberus_remember",
  loginPath: "/login",
  /**
   * Post-login destination. The new front-end's home is the AI Chat page
   * (the old /dashboard was retired in the front-end update — see CHANGELOG).
   */
  dashboardPath: "/chat",
  otpLength: 6,
  // Verification OTP: 90 seconds — the 01:30 countdown from the design
  // (mirrors backend OTP_EXPIRE_SECONDS).
  otpExpirySeconds: 90,
  // Password-reset code: 05:00 countdown (design's forgot-flow timer).
  resetCodeSeconds: 300,
  otpResendCooldownSeconds: 30,
  passwordMinLength: 8,
} as const;
