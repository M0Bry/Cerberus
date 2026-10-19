/**
 * Register Page (new design) — ported from the new front-end's register-compact.html.
 *
 * Real wiring:
 *  - POST /auth/register (authApi) → then /verify-email
 *  - photo upload: validated client-side (JPG/SVG/PNG/HEIC), shrunk to a 128px
 *    data-URL preview. ⚠️ The backend RegisterRequest has no photo field yet,
 *    so the selected photo is kept in localStorage ("cerberus_photo") until the
 *    backend adds a profile-image endpoint (phase 2 — see CHANGE_LIST.md).
 */
import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import AuthLayout from "../components/layout/AuthLayout";
import { useReveal } from "../hooks/useReveal";
import { authApi, type RegisterPayload } from "../api/authApi";
import { AUTH_CONFIG } from "../config/auth";
import {
  checkCompanyName,
  checkEmail,
  checkFullName,
  checkJobTitle,
  checkPassword,
  checkPasswordMatch,
  checkPhone,
} from "../utils/validators";

const PHOTO_KEY = "cerberus_photo";
const OK_TYPES = /\.(jpe?g|png|svg|heic)$/i;

export default function RegisterPage() {
  const navigate = useNavigate();
  const revealRef = useReveal<HTMLFormElement>();
  const fileRef = useRef<HTMLInputElement>(null);
  const [form, setForm] = useState({
    name: "",
    company: "",
    title: "",
    email: "",
    phone: "",
    password: "",
    password2: "",
  });
  const [photoName, setPhotoName] = useState("");
  const [photoData, setPhotoData] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [showPw2, setShowPw2] = useState(false);
  const [error, setError] = useState("");

  const update = (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((p) => ({ ...p, [field]: e.target.value }));

  const setPhoto = (file: File | undefined) => {
    setError("");
    if (!file) return;
    if (!OK_TYPES.test(file.name)) {
      setError("Only JPG, SVG, PNG and HEIC files are accepted.");
      return;
    }
    setPhotoName(file.name);
    setPhotoData("");
    // Shrink to a 128px PNG data-URL (matches the mock's behaviour).
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = c.height = 128;
      const s = Math.min(img.naturalWidth, img.naturalHeight) || 128;
      const ctx = c.getContext("2d");
      if (ctx) {
        ctx.drawImage(img, (img.naturalWidth - s) / 2, (img.naturalHeight - s) / 2, s, s, 0, 0, 128, 128);
        setPhotoData(c.toDataURL("image/png"));
      }
      URL.revokeObjectURL(url);
    };
    img.onerror = () => URL.revokeObjectURL(url);
    img.src = url;
  };

  const registerMutation = useMutation<any, any, RegisterPayload>({
    mutationFn: (data) => authApi.register(data).then((r) => r.data),
    onSuccess: (_data) => {
      try {
        if (photoData) localStorage.setItem(PHOTO_KEY, photoData);
        else localStorage.removeItem(PHOTO_KEY);
      } catch {
        /* storage unavailable */
      }
      navigate("/verify-email", { state: { email: form.email.trim() } });
    },
    onError: (err) => {
      setError(
        err?.response?.data?.error?.message || err?.response?.data?.detail || err?.message || "Registration failed"
      );
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!photoName) {
      setError("Please upload your photo.");
      return;
    }
    // Client-side validation (UX layer — the backend re-checks everything).
    const nameErr = checkFullName(form.name);
    if (nameErr) return setError(nameErr);
    const companyErr = checkCompanyName(form.company);
    if (companyErr) return setError(companyErr);
    const titleErr = checkJobTitle(form.title);
    if (titleErr) return setError(titleErr);
    const emailErr = checkEmail(form.email);
    if (emailErr) return setError(emailErr);
    const phoneErr = checkPhone(form.phone, true);
    if (phoneErr) return setError(phoneErr);
    const pwErr = checkPassword(form.password);
    if (pwErr) return setError(pwErr);
    const matchErr = checkPasswordMatch(form.password, form.password2);
    if (matchErr) return setError(matchErr);
    const payload: RegisterPayload = {
      full_name: form.name.trim(),
      company_name: form.company.trim(),
      job_title: form.title.trim(),
      email: form.email.trim(),
      phone_number: form.phone.trim() || undefined,
      password: form.password,
      confirm_password: form.password2,
    };
    registerMutation.mutate(payload);
  };

  return (
    <AuthLayout backTo="/" backLabel="Back">
      <form id="regForm" ref={revealRef} className="rc-card fade-up" noValidate onSubmit={handleSubmit}>
        <aside className="rc-side">
          <h1 className="rc-title">
            Create
            <br />
            Account
          </h1>
          <p className="rc-sub">Register your organization to begin intelligent security assessments.</p>
          <p className="auth-foot rc-foot">
            Already registered? <Link to="/login">Log In</Link>
          </p>
        </aside>

        <div className="rc-form">
          {error && <div id="regAlert" className="alert show err">{error}</div>}

          <div className="form-group rc-photo">
            <label>Your Photo</label>
            <label className={`upload-box${photoName ? " has-file" : ""}`}>
              <i className="fas fa-cloud-arrow-up" />
              <span className="upload-text">
                {photoName ? (
                  <>Selected: {photoName}</>
                ) : (
                  <>
                    Click or drop a file
                    <br />
                    <small>JPG · SVG · PNG · HEIC</small>
                  </>
                )}
              </span>
              <input
                ref={fileRef}
                type="file"
                accept=".jpg,.jpeg,.png,.svg,.heic,image/heic"
                hidden
                onChange={(e) => setPhoto(e.target.files?.[0])}
              />
            </label>
          </div>

          <div className="rc-grid">
            <div className="form-group rc-span">
              <label>Full Name</label>
              <input name="name" required maxLength={100} placeholder="John Doe" value={form.name} onChange={update("name")} />
            </div>
            <div className="form-group">
              <label>Company Name</label>
              <input name="company" required maxLength={100} placeholder="Acme Corp" value={form.company} onChange={update("company")} />
            </div>
            <div className="form-group">
              <label>Job Title</label>
              <input name="title" required maxLength={60} placeholder="CISO" value={form.title} onChange={update("title")} />
            </div>
            <div className="form-group">
              <label>Corporate Email</label>
              <input name="email" type="email" required maxLength={254} placeholder="john@acme.com" value={form.email} onChange={update("email")} />
            </div>
            <div className="form-group">
              <label>Phone Number</label>
              <input name="phone" type="tel" required maxLength={20} placeholder="+20 100 000 0000" value={form.phone} onChange={update("phone")} />
            </div>
            <div className="form-group">
              <label>Password</label>
              <div className="pw-wrap">
                <input
                  id="regPw"
                  name="password"
                  type={showPw ? "text" : "password"}
                  minLength={AUTH_CONFIG.passwordMinLength}
                  maxLength={128}
                  required
                  placeholder="••••••••"
                  value={form.password}
                  onChange={update("password")}
                />
                <button type="button" className={`pw-toggle fas fa-${showPw ? "eye-slash" : "eye"}`} aria-label="Toggle password" onClick={() => setShowPw((v) => !v)} />
              </div>
            </div>
            <div className="form-group">
              <label>Confirm Password</label>
              <div className="pw-wrap">
                <input
                  id="regPw2"
                  name="confirm"
                  type={showPw2 ? "text" : "password"}
                  minLength={AUTH_CONFIG.passwordMinLength}
                  maxLength={128}
                  required
                  placeholder="••••••••"
                  value={form.password2}
                  onChange={update("password2")}
                />
                <button type="button" className={`pw-toggle fas fa-${showPw2 ? "eye-slash" : "eye"}`} aria-label="Toggle password" onClick={() => setShowPw2((v) => !v)} />
              </div>
            </div>
          </div>

          <button className="btn btn-primary rc-submit" disabled={registerMutation.isPending}>
            <i className="fas fa-shield-halved" />{" "}
            {registerMutation.isPending ? "Creating secure account…" : "Create Secure Account"}
          </button>
        </div>
      </form>
    </AuthLayout>
  );
}
