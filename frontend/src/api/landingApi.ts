/**
 * Landing API — Public endpoints (stats, contact).
 */
import axiosAuth from "./axiosAuth";

export const landingApi = {
  getStats: () => axiosAuth.get("/public/stats"),
  sendContact: (data: { name: string; email: string; subject: string; message: string }) =>
    axiosAuth.post("/public/contact", data),
};
