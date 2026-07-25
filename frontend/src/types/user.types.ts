/**
 * User Types — Canonical definitions matching the backend User model.
 *
 * Backend UserRole enum: user, admin, super_admin
 * Backend UserStatus enum: pending_verification, verified, suspended, deleted
 */

export type UserRole = "user" | "admin" | "super_admin";
export type UserStatus = "pending_verification" | "verified" | "suspended" | "deleted";

export interface User {
  id: string;
  full_name: string;
  email: string;
  company_name: string;
  job_title: string;
  phone_number?: string;
  company_location?: string;
  avatar_url?: string;
  role: UserRole;
  status: UserStatus;
  mfa_enabled: boolean;
  created_at: string;
  verified_at?: string;
  last_login_at?: string;
}

export interface UserProfile extends User {
  // Extended profile fields
}

export interface UserUpdate {
  full_name?: string;
  phone_number?: string;
  company_name?: string;
  job_title?: string;
  company_location?: string;
}
