/**
 * Validators — Form validation utilities (client-side, UX layer).
 *
 * SECURITY MODEL
 * - Client-side validation is a UX/latency layer only. The backend is the
 *   source of truth and re-validates everything — nothing here is trusted.
 * - Every validator is a PURE function: no DOM, no eval/Function, no
 *   network, no prototype-sensitive object mutation. They return a plain
 *   error string ("" = valid) or a boolean.
 * - Error strings are fixed, developer-authored literals. User input is
 *   NEVER interpolated into them, and callers render them as plain text
 *   (React escapes) — so validation output can't be an XSS vector.
 * - All regexes are linear (no nested quantifiers) — no ReDoS surface.
 */

export const LIMITS = {
  fullName: { min: 2, max: 100 },
  companyName: { min: 1, max: 100 },
  jobTitle: { min: 1, max: 60 },
  email: { max: 254 }, // RFC 5321
  phone: { min: 5, max: 20 },
  password: { min: 8, max: 128 },
  otpLength: 6,
  contact: { name: 120, subject: 200, messageMin: 10, messageMax: 5000 },
  chatMessage: { min: 1, max: 4000 },
  signatureName: { min: 3, max: 60 },
  projectName: { min: 2, max: 100 },
} as const;

/**
 * Strip control characters (except newline/tab) and trim. Pure string op.
 * Used as input hygiene before validation; display is always escaped by
 * React, so no tag-stripping is needed or done here.
 */
export function cleanText(v: string): string {
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim();
}

export function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Email format + RFC length cap. Returns "" when valid. */
export function checkEmail(v: string): string {
  const s = cleanText(v);
  if (!s) return "Email is required.";
  if (s.length > LIMITS.email.max) return "Email is too long.";
  if (!validateEmail(s)) return "Enter a valid email address.";
  return "";
}

/** Phone: optional when allowEmpty; 5–20 chars of digits, spaces, + - (). */
export function checkPhone(v: string, allowEmpty = true): string {
  const s = cleanText(v);
  if (!s) return allowEmpty ? "" : "Phone number is required.";
  if (s.length > LIMITS.phone.max) return "Phone number is too long.";
  if (!/^[+\d][\d\s\-()]{3,19}$/.test(s)) return "Enter a valid phone number.";
  return "";
}

export function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (password.length < 8) errors.push("At least 8 characters");
  if (!/[A-Z]/.test(password)) errors.push("One uppercase letter");
  if (!/[a-z]/.test(password)) errors.push("One lowercase letter");
  if (!/[0-9]/.test(password)) errors.push("One number");
  return { valid: errors.length === 0, errors };
}

/** Password rules (min length, strength, max length). Returns "" when valid. */
export function checkPassword(v: string): string {
  if (!v) return "Password is required.";
  if (v.length > LIMITS.password.max) return "Password is too long.";
  if (v.length < LIMITS.password.min)
    return `Password must be at least ${LIMITS.password.min} characters.`;
  const r = validatePassword(v);
  if (!r.valid) return `Password needs: ${r.errors.join(", ")}.`;
  return "";
}

/** Two passwords match (non-empty implied by caller rules). */
export function checkPasswordMatch(a: string, b: string): string {
  return a === b ? "" : "Passwords do not match.";
}

/** Generic required + max-length text field. label is a fixed literal. */
export function checkText(
  v: string,
  label: string,
  { min = 1, max }: { min?: number; max: number }
): string {
  const s = cleanText(v);
  if (!s) return `${label} is required.`;
  if (s.length > max) return `${label} is too long (max ${max} characters).`;
  if (s.length < min) return `${label} needs at least ${min} characters.`;
  return "";
}

/** Full name: letters, spaces, .-' only (keeps the value display-safe). */
export function checkFullName(v: string): string {
  const s = cleanText(v);
  if (!s) return "Full name is required.";
  if (s.length > LIMITS.fullName.max) return "Full name is too long.";
  if (s.length < LIMITS.fullName.min) return "Full name is too short.";
  if (!/^[A-Za-z][A-Za-z\s.'\-]*$/.test(s))
    return "Full name can only contain letters, spaces, apostrophes, dots and hyphens.";
  return "";
}

/** Company name: letters/digits and common separators. */
export function checkCompanyName(v: string): string {
  const s = cleanText(v);
  if (!s) return "Company name is required.";
  if (s.length > LIMITS.companyName.max) return "Company name is too long.";
  if (!/^[A-Za-z0-9][A-Za-z0-9\s.&'()+-]*$/.test(s))
    return "Company name can only contain letters, numbers and basic punctuation.";
  return "";
}

export function checkJobTitle(v: string): string {
  return checkText(v, "Job title", LIMITS.jobTitle);
}

export function validateDomain(domain: string): boolean {
  return /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(domain);
}

export function validateIP(ip: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split(".").every((o) => +o >= 0 && +o <= 255);
}

export function validateOTP(otp: string): boolean {
  return /^\d{6}$/.test(otp);
}

/** 6-digit OTP, fixed-length message. */
export function checkOTP(v: string): string {
  if (!v) return "Enter the 6-digit code.";
  if (!validateOTP(v)) return "The code must be exactly 6 digits.";
  return "";
}

/** Contact form fields (mirrors backend ContactMessageCreate). */
export function checkContactField(field: "name" | "subject" | "message", v: string): string {
  const s = cleanText(v);
  if (field === "name")
    return checkText(s, "Name", { min: 2, max: LIMITS.contact.name });
  if (field === "subject")
    return checkText(s, "Subject", { min: 1, max: LIMITS.contact.subject });
  if (!s) return "Message is required.";
  if (s.length > LIMITS.contact.messageMax)
    return `Message is too long (max ${LIMITS.contact.messageMax} characters).`;
  if (s.length < LIMITS.contact.messageMin)
    return `Message needs at least ${LIMITS.contact.messageMin} characters.`;
  return "";
}

/** Chat message: non-empty, capped (backend caps too — double safety). */
export function checkChatMessage(v: string): string {
  const s = cleanText(v);
  if (!s) return "Type a message first.";
  if (s.length > LIMITS.chatMessage.max)
    return `Message is too long (max ${LIMITS.chatMessage.max} characters).`;
  return "";
}

/** Typed legal signature name (RoE): deliberate, real-person text. */
export function checkSignatureName(v: string): string {
  const s = cleanText(v);
  if (!s) return "Type your full legal name to sign.";
  if (s.length > LIMITS.signatureName.max) return "Signature is too long.";
  if (s.length < LIMITS.signatureName.min) return "Signature is too short.";
  if (!/^[A-Za-z][A-Za-z\s.'\-]*$/.test(s))
    return "Signature can only contain letters, spaces, apostrophes, dots and hyphens.";
  return "";
}
