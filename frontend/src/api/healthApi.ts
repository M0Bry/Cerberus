/**
 * Health API — System health check (public + protected).
 */
import axiosAuth from "./axiosAuth";
import axiosInstance from "./axiosInstance";

export const healthApi = {
  publicHealth: () => axiosAuth.get("/health"),
  protectedHealth: () => axiosInstance.get("/health/detailed"),
};
