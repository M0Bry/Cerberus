/**
 * User API — Profile CRUD, avatar upload, delete account.
 */
import axiosInstance from "./axiosInstance";

export const userApi = {
  getProfile: () => axiosInstance.get("/users/me"),
  updateProfile: (data: any) => axiosInstance.put("/users/me", data),
  uploadAvatar: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return axiosInstance.post("/users/me/avatar", fd, { headers: { "Content-Type": "multipart/form-data" } });
  },
  deleteAccount: () => axiosInstance.delete("/users/me"),
};
