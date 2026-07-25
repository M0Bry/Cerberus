/**
 * Auth Types — Authentication-related type definitions.
 */

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

export interface LoginPayload {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface VerifyOTPPayload {
  email: string;
  otp: string;
}

export interface ResendOTPPayload {
  email: string;
}
