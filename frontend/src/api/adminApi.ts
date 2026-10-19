/**
 * Admin API — Users, audit logs, admin dashboard, contact inbox.
 *
 * Contract (backend/app/api/v1/endpoints/admin.py):
 *   GET  /admin/dashboard
 *   GET  /admin/users
 *   GET  /admin/audit-logs
 *   GET  /admin/contact-messages        → {total, unread, items[]}
 *   PATCH /admin/contact-messages/:id   → mark read
 *   POST /admin/contact-messages/:id/reply → {success, message, delivery, delivery_note}
 *
 * NOTE: the new admin UI also lists engagements — that data comes from
 * engagementApi.list (there is no /admin/engagements endpoint on the backend).
 */
import axiosAuth from "./axiosAuth";
import axiosInstance from "./axiosInstance";
import type { AdminUserRow, AdminAuditEntry } from "../types";

export interface AdminPortalLoginResponse {
  success: boolean;
  message: string;
  requires_otp: boolean;
  expires_in: number;
}

export interface AdminPortalTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface AdminContactItem {
  id: string;
  name: string;
  email: string;
  subject: string;
  message: string;
  user_id: string | null;
  registered: boolean;
  reply: string | null;
  replied_at: string | null;
  ip_address: string | null;
  is_read: boolean;
  created_at: string;
}

export interface AdminContactList {
  total: number;
  unread: number;
  items: AdminContactItem[];
}

export interface AdminContactReplyResult {
  success: boolean;
  message: AdminContactItem;
  delivery: "notification" | "email" | "none";
  delivery_note: string | null;
}

export const adminApi = {
  /* ── Hardened admin portal (separate from /auth/login) ──
   * Hidden two-step login: credentials → emailed one-time code (90s).
   * Admin accounts are rejected on the standard login endpoint. */
  portalLogin: (data: { email: string; password: string }) =>
    axiosAuth.post<AdminPortalLoginResponse>("/admin/login", data),
  portalVerify: (data: { email: string; otp: string }) =>
    axiosAuth.post<AdminPortalTokenResponse>("/admin/verify", data),

  getDashboard: () => axiosInstance.get("/admin/dashboard"),
  getUsers: (params?: { page?: number; page_size?: number; search?: string }) =>
    axiosInstance.get<{ success: boolean; total?: number; items: AdminUserRow[] }>(
      "/admin/users",
      { params }
    ),
  getAuditLogs: (params?: { page?: number; page_size?: number }) =>
    axiosInstance.get<{ success: boolean; total?: number; items: AdminAuditEntry[] }>(
      "/admin/audit-logs",
      { params }
    ),
  getContactMessages: (params?: { page?: number; page_size?: number; unread_only?: boolean }) =>
    axiosInstance.get<AdminContactList>("/admin/contact-messages", { params }),
  markContactRead: (id: string) => axiosInstance.patch<AdminContactItem>(`/admin/contact-messages/${id}`),
  replyContact: (id: string, message: string) =>
    axiosInstance.post<AdminContactReplyResult>(`/admin/contact-messages/${id}/reply`, { message }),
};
