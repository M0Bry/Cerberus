/**
 * Login Page — User authentication.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import ParticleBackground from "../components/common/ParticleBackground";
import CerberusLogo from "../components/common/CerberusLogo";
import { authService } from "../services/auth";
import { useAuthStore } from "../stores/authStore";

interface LoginResponse {
  access_token: string;
  refresh_token: string;
}

interface LoginError {
  response?: {
    data?: {
      error?: {
        message?: string;
      };
    };
  };
  message?: string;
}

export default function LoginPage() {
  const navigate = useNavigate();
  const { setTokens } = useAuthStore();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const loginMutation = useMutation<LoginResponse, LoginError, { email: string; password: string }>({
    mutationFn: authService.login,
    onSuccess: (data) => {
      setTokens(data.access_token, data.refresh_token);
      navigate("/dashboard");
    },
    onError: (err) => {
      const message = err.response?.data?.error?.message || err.message || "Login failed";
      setError(message);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    loginMutation.mutate({ email, password });
  };

  return (
    <div className="min-h-screen relative flex items-center justify-center px-4">
      <ParticleBackground />

      <div className="relative z-10 w-full max-w-md">
        <div className="text-center mb-8">
          <CerberusLogo size="md" />
          <h2 className="mt-4 text-2xl font-bold text-white">Welcome Back</h2>
          <p className="mt-2 text-sm text-gray-400">
            Sign in to access your security dashboard
          </p>
        </div>

        <form onSubmit={handleSubmit} className="cyber-card space-y-5">
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm text-gray-300 mb-1">Email</label>
            <input
              type="email"
              className="cyber-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@company.com"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Password</label>
            <input
              type="password"
              className="cyber-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loginMutation.isPending}
            className="btn-glow w-full text-center disabled:opacity-50"
          >
            {loginMutation.isPending ? "Signing In..." : "Sign In"}
          </button>

          <p className="text-center text-sm text-gray-400">
            Don't have an account?{" "}
            <button
              type="button"
              onClick={() => navigate("/register")}
              className="text-cerberus-blue hover:underline"
            >
              Create Account
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
