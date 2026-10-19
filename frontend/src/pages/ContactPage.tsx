/**
 * Contact Page (Public).
 *
 * POSTs to /public/contact (same endpoint as the landing section). The
 * message lands in the admin inbox; the admin reply reaches the sender's
 * Notifications when they have an account.
 *
 * Validation is client-side (UX) only — the backend re-validates the same
 * rules (ContactMessageCreate). Errors are rendered as plain text (React
 * escapes), so user input can never become an XSS vector here.
 */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import Navbar from "../components/layout/Navbar";
import Footer from "../components/layout/Footer";
import { landingApi } from "../api/landingApi";
import { checkContactField, checkEmail, LIMITS } from "../utils/validators";

export default function ContactPage() {
  const [form, setForm] = useState({ name: "", email: "", subject: "", message: "" });
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);

  const update =
    (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setForm((p) => ({ ...p, [field]: e.target.value }));

  const sendMutation = useMutation({
    mutationFn: async () =>
      (
        await landingApi.sendContact({
          name: form.name.trim(),
          email: form.email.trim(),
          subject: form.subject.trim(),
          message: form.message.trim(),
        })
      ).data,
    onSuccess: () => {
      setSent(true);
      setError("");
    },
    onError: (err: any) => {
      const detail =
        err?.response?.data?.detail || err?.response?.data?.error?.message || "Something went wrong sending your message. Please try again.";
      setError(Array.isArray(detail) ? detail[0]?.msg || "Please check your message and try again." : String(detail));
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    // Client-side validation (the backend re-checks everything).
    const nameErr = checkContactField("name", form.name);
    if (nameErr) return setError(nameErr);
    const emailErr = checkEmail(form.email);
    if (emailErr) return setError(emailErr);
    const subjectErr = checkContactField("subject", form.subject);
    if (subjectErr) return setError(subjectErr);
    const messageErr = checkContactField("message", form.message);
    if (messageErr) return setError(messageErr);
    sendMutation.mutate();
  };

  return (
    <div className="min-h-screen bg-cerberus-dark">
      <Navbar />
      <div className="pt-24 pb-16 px-4 max-w-2xl mx-auto">
        <h1 className="text-4xl font-bold text-white mb-4">Contact Us</h1>
        <p className="text-gray-400 mb-8">Have questions about Cerberus AI? Reach out and we'll get back to you within 24 hours.</p>

        {sent ? (
          <div className="cyber-card p-6 text-center">
            <p className="text-emerald-400 text-lg font-semibold">
              <i className="fas fa-circle-check mr-2" />
              Thank you — your message has been sent. Our team will get back to you.
            </p>
          </div>
        ) : (
          <form className="cyber-card space-y-4" noValidate onSubmit={handleSubmit}>
            {error && <div className="text-rose-400 text-sm" role="alert">{error}</div>}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-300 mb-1 block">Name</label>
                <input className="cyber-input" maxLength={LIMITS.contact.name} value={form.name} onChange={update("name")} />
              </div>
              <div>
                <label className="text-sm text-gray-300 mb-1 block">Email</label>
                <input type="email" maxLength={LIMITS.email.max} className="cyber-input" value={form.email} onChange={update("email")} />
              </div>
            </div>
            <div>
              <label className="text-sm text-gray-300 mb-1 block">Subject</label>
              <input className="cyber-input" maxLength={LIMITS.contact.subject} value={form.subject} onChange={update("subject")} />
            </div>
            <div>
              <label className="text-sm text-gray-300 mb-1 block">Message</label>
              <textarea className="cyber-input min-h-[120px]" maxLength={LIMITS.contact.messageMax} value={form.message} onChange={update("message")} />
            </div>
            <button type="submit" className="btn-glow w-full text-center" disabled={sendMutation.isPending}>
              {sendMutation.isPending ? "Sending…" : "Send Message"}
            </button>
          </form>
        )}
      </div>
      <Footer />
    </div>
  );
}
