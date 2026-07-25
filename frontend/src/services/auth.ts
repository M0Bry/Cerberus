/**
 * Auth Service — API calls for authentication.
 */

import apiClient from "./api";

export const authService = {
  register: (data: {
    full_name: string;
    company_name: string;
    job_title: string;
    email: string;
    phone_number?: string;
    company_location?: string;
    password: string;
    confirm_password: string;
  }) => apiClient.post("/auth/register", data),

  verifyOtp: (data: { email: string; otp: string }) =>
    apiClient.post("/auth/verify-otp", data),

  resendOtp: (data: { email: string }) =>
    apiClient.post("/auth/resend-otp", data),

  login: (data: { email: string; password: string }) =>
    apiClient.post("/auth/login", data),

  logout: () => apiClient.post("/auth/logout"),

  refreshToken: (refreshToken: string) =>
    apiClient.post("/auth/refresh", { refresh_token: refreshToken }),
};
