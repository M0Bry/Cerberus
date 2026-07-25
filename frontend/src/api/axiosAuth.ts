/**
 * Auth Axios — No auth header (for login/register/verify endpoints).
 */
import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "/api/v1";

const axiosAuth = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

export default axiosAuth;
