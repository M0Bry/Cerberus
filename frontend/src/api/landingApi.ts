/**
 * Landing API — Public endpoints (stats, contact).
 *
 * sendContact uses the auth-aware instance ON PURPOSE: the landing form
 * is public (guests can send), but if the visitor happens to be logged
 * in the Bearer token is attached and the backend links the message to
 * their account — which enables the admin to reply straight to their
 * Notifications page.
 */
import axiosAuth from "./axiosAuth";
import axiosInstance from "./axiosInstance";

export const landingApi = {
  getStats: () => axiosAuth.get("/public/stats"),
  sendContact: (data: { name: string; email: string; subject: string; message: string }) =>
    axiosInstance.post("/public/contact", data),
};
