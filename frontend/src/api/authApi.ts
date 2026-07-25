/**
 * Auth API — Register, Login, Logout, Verify, Resend, Refresh.
 * Uses axiosAuth (no JWT header) for unauthenticated endpoints.
 */
import axiosAuth from "./axiosAuth";

export const authApi = {
  register: (data: any) => axiosAuth.post("/auth/register", data),
  login: (data: { email: string; password: string }) => axiosAuth.post("/auth/login", data),
  verifyOtp: (data: { email: string; otp: string }) => axiosAuth.post("/auth/verify-otp", data),
  resendOtp: (data: { email: string }) => axiosAuth.post("/auth/resend-otp", data),
  refreshToken: (token: string) => axiosAuth.post("/auth/refresh", { refresh_token: token }),
};
