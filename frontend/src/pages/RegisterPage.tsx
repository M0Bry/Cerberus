/**
 * Registration Page — Full registration form.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import AuthLayout from "../components/layout/AuthLayout";
import Input from "../components/ui/Input";
import PasswordInput from "../components/ui/PasswordInput";
import Button from "../components/ui/Button";
import { authService } from "../services/auth";

interface RegisterPayload {
  full_name: string;
  company_name: string;
  job_title: string;
  email: string;
  phone_number?: string;
  company_location?: string;
  password: string;
  confirm_password: string;
}

interface RegisterResponse {
  success: boolean;
  user_id: string;
  email_masked: string;
}

interface ApiError {
  response?: { data?: { error?: { message?: string } } };
  message?: string;
}

export default function RegisterPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState<RegisterPayload>({
    full_name: "",
    company_name: "",
    job_title: "",
    email: "",
    phone_number: "",
    company_location: "",
    password: "",
    confirm_password: "",
  });
  const [error, setError] = useState("");

  const registerMutation = useMutation<
    RegisterResponse,
    ApiError,
    RegisterPayload
  >({
    mutationFn: (payload) => authService.register(payload),
    onSuccess: (data) => {
      navigate("/verify-email", {
        state: {
          email: form.email,
          emailMasked: data.email_masked,
        },
      });
    },
    onError: (err) => {
      setError(err.response?.data?.error?.message || "Registration failed");
    },
  });

  const updateField = (field: keyof RegisterPayload, value: string) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    registerMutation.mutate(form);
  };

  return (
    <AuthLayout>
      <h2 className="text-2xl font-bold text-white mb-2">Create Your Account</h2>
      <p className="text-gray-400 mb-6">Begin your security assessment journey</p>

      <form onSubmit={handleSubmit} className="cyber-card space-y-4">
        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Full Name *"
            value={form.full_name}
            onChange={(e) => updateField("full_name", e.target.value)}
            required
          />
          <Input
            label="Job Title *"
            value={form.job_title}
            onChange={(e) => updateField("job_title", e.target.value)}
            required
          />
        </div>

        <Input
          label="Company Name *"
          value={form.company_name}
          onChange={(e) => updateField("company_name", e.target.value)}
          required
        />
        <Input
          label="Corporate Email *"
          type="email"
          value={form.email}
          onChange={(e) => updateField("email", e.target.value)}
          required
        />

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Phone Number"
            type="tel"
            value={form.phone_number || ""}
            onChange={(e) => updateField("phone_number", e.target.value)}
          />
          <Input
            label="Company Location"
            value={form.company_location || ""}
            onChange={(e) => updateField("company_location", e.target.value)}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <PasswordInput
            label="Password *"
            value={form.password}
            onChange={(e) => updateField("password", e.target.value)}
            minLength={8}
            required
          />
          <PasswordInput
            label="Confirm Password *"
            value={form.confirm_password}
            onChange={(e) => updateField("confirm_password", e.target.value)}
            minLength={8}
            required
          />
        </div>

        <Button type="submit" loading={registerMutation.isPending} className="w-full">
          Create Account
        </Button>

        <p className="text-center text-sm text-gray-400">
          Already have an account?{" "}
          <button type="button" onClick={() => navigate("/login")} className="text-cerberus-blue hover:underline">
            Sign In
          </button>
        </p>
      </form>
    </AuthLayout>
  );
}
