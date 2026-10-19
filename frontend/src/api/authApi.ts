/**
 * Auth API — Register, Login, Logout, Verify, Resend, Refresh, Password Reset.
 * Uses axiosAuth (no JWT header) for unauthenticated endpoints.
 *
 * Contract (backend/app/api/v1/endpoints/auth.py):
 *   POST /auth/register      {full_name, company_name, job_title, email, phone_number?,
 *                             company_location?, password, confirm_password}
 *   POST /auth/verify-otp    {email, otp}
 *   POST /auth/resend-otp    {email}
 *   POST /auth/login         {email, password}          → {access_token, refresh_token, user}
 *   POST /auth/refresh       {refresh_token}
 *   POST /auth/logout        (Bearer)
 *
 * Password reset (new front-end forgot flow) — backend endpoints expected at:
 *   POST /auth/forgot-password {email}
 *   POST /auth/reset-password  {email, otp, new_password}
 * ⚠️ These two endpoints are NOT in the backend yet (flagged for phase 2).
 *    The UI degrades gracefully with a clear message when they return 404.
 */
import axiosAuth from "./axiosAuth";

export interface RegisterPayload {
  full_name: string;
  company_name: string;
  job_title: string;
  email: string;
  phone_number?: string;
  company_location?: string;
  password: string;
  confirm_password: string;
}

export const authApi = {
  register: (data: RegisterPayload) => axiosAuth.post("/auth/register", data),
  verifyOtp: (data: { email: string; otp: string }) => axiosAuth.post("/auth/verify-otp", data),
  resendOtp: (data: { email: string }) => axiosAuth.post("/auth/resend-otp", data),
  login: (data: { email: string; password: string }) => axiosAuth.post("/auth/login", data),
  refreshToken: (token: string) => axiosAuth.post("/auth/refresh", { refresh_token: token }),
  logout: () => axiosAuth.post("/auth/logout"),
  /** ⚠️ Backend endpoint pending (phase 2). */
  forgotPassword: (data: { email: string }) => axiosAuth.post("/auth/forgot-password", data),
  /** ⚠️ Backend endpoint pending (phase 2). */
  resetPassword: (data: { email: string; otp: string; new_password: string }) =>
    axiosAuth.post("/auth/reset-password", data),
};
