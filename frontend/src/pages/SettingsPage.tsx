/**
 * Settings Page — ported from the new front-end's settings.html + js/settings.js.
 *
 * Wiring (real backend where it exists):
 *   Personal info  → PUT /users/me
 *   Password       → POST /users/me/change-password
 *   MFA            → no backend endpoint yet → device-local preference + note
 *   Notifications  → no backend endpoint yet → device-local preferences
 *   Sessions       → no backend endpoint yet → current device only
 *   Login activity → no backend endpoint yet → empty state
 *   Account status → real user (verified flag) + local plan
 *
 * Photo: the backend has no upload endpoint yet, so the photo is shrunk to a
 * 128px data-URL and kept in localStorage ("cerberus_photo") — same behaviour
 * as register, clearly flagged in the flash message.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { userApi } from "../api/userApi";
import { useAuthStore } from "../store/useAuthStore";
import type { User } from "../types";
import {
  checkCompanyName,
  checkFullName,
  checkJobTitle,
  checkPassword,
  checkPasswordMatch,
  checkPhone,
} from "../utils/validators";

const OK_TYPES = /\.(jpe?g|png|svg|heic)$/i;
const PHOTO_KEY = "cerberus_photo";
const SET_KEY = "cerberus_settings";

const CATS = [
  { id: "progress", label: "Assessment progress", desc: "Updates while an assessment is running." },
  { id: "completed", label: "Assessment completed", desc: "When an assessment finishes and its report is ready." },
  { id: "attention", label: "Needs attention", desc: "The site could not finish, or the work is paused." },
  { id: "reports", label: "New reports", desc: "A PDF report is added to your Reports list." },
  { id: "replies", label: "Replies from Cerberus team", desc: "Answers to messages you sent us." },
];

function readSet(): { mfa: boolean; notify: { email: Record<string, boolean>; app: Record<string, boolean> } } {
  const allOn = () => Object.fromEntries(CATS.map((c) => [c.id, true]));
  try {
    const saved = JSON.parse(localStorage.getItem(SET_KEY) || "{}");
    return {
      mfa: !!saved.mfa,
      notify: {
        email: { ...allOn(), ...(saved.notify || {}).email },
        app: { ...allOn(), ...(saved.notify || {}).app },
      },
    };
  } catch {
    return { mfa: false, notify: { email: Object.fromEntries(CATS.map((c) => [c.id, true])), app: Object.fromEntries(CATS.map((c) => [c.id, true])) } };
  }
}

function deviceName(): string {
  const ua = navigator.userAgent || "";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Unknown OS";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  return `${br} on ${os}`;
}

export default function SettingsPage() {
  const storeUser = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const { data: fresh } = useQuery({
    queryKey: ["me"],
    queryFn: async () => (await userApi.getProfile()).data as User,
    staleTime: 60_000,
  });
  const user: User | null = fresh || storeUser;

  /* ── personal ── */
  const [personal, setPersonal] = useState<{
    full_name: string;
    job_title: string;
    company_name: string;
    phone_number: string | null;
  }>({
    full_name: user?.full_name || "",
    job_title: user?.job_title || "",
    company_name: user?.company_name || "",
    phone_number: user?.phone_number || "",
  });
  const [msgPersonal, setMsgPersonal] = useState<{ t: string; ok: boolean } | null>(null);

  /* fill the form once the profile query resolves (user may load after mount) */
  const userId = user?.id;
  useEffect(() => {
    if (userId) {
      setPersonal({
        full_name: user?.full_name || "",
        job_title: user?.job_title || "",
        company_name: user?.company_name || "",
        phone_number: user?.phone_number || "",
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);
  const savePersonal = useMutation({
    mutationFn: (d: typeof personal) => userApi.updateProfile(d).then((r) => r.data),
    onSuccess: (data: any) => {
      if (data) setUser({ ...(user as User), ...data });
      setMsgPersonal({ t: "Saved.", ok: true });
    },
    onError: (err: any) =>
      setMsgPersonal({
        t: err?.response?.data?.error?.message || err?.response?.data?.detail || "Could not save changes.",
        ok: false,
      }),
  });

  /* ── photo ── */
  const [photo, setPhoto] = useState<string>(() => {
    try {
      return localStorage.getItem(PHOTO_KEY) || "";
    } catch {
      return "";
    }
  });
  const [msgPhoto, setMsgPhoto] = useState<{ t: string; ok: boolean } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const onPhoto = (file?: File) => {
    if (!file) return;
    if (!OK_TYPES.test(file.name)) {
      setMsgPhoto({ t: "Only JPG, SVG, PNG and HEIC files are accepted.", ok: false });
      return;
    }
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = c.height = 128;
      const s = Math.min(img.naturalWidth, img.naturalHeight) || 128;
      c.getContext("2d")?.drawImage(img, (img.naturalWidth - s) / 2, (img.naturalHeight - s) / 2, s, s, 0, 0, 128, 128);
      URL.revokeObjectURL(url);
      const data = c.toDataURL("image/png");
      try {
        localStorage.setItem(PHOTO_KEY, data);
      } catch {
        /* ignore */
      }
      setPhoto(data);
      setMsgPhoto({ t: "Photo updated (stored on this device until the backend adds an upload endpoint).", ok: true });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      setMsgPhoto({ t: "This browser cannot preview that file, so the photo was not saved. Try JPG or PNG.", ok: false });
    };
    img.src = url;
  };

  const removePhoto = () => {
    try {
      localStorage.removeItem(PHOTO_KEY);
    } catch {
      /* ignore */
    }
    setPhoto("");
    setMsgPhoto({ t: "Photo removed.", ok: true });
  };

  /* ── password ── */
  const [pw, setPw] = useState({ cur: "", new1: "", new2: "" });
  const [msgPassword, setMsgPassword] = useState<{ t: string; ok: boolean } | null>(null);
  const changePw = useMutation({
    mutationFn: () =>
      userApi
        .changePassword({ current_password: pw.cur, new_password: pw.new1, confirm_new_password: pw.new2 })
        .then((r) => r.data),
    onSuccess: () => {
      setPw({ cur: "", new1: "", new2: "" });
      setMsgPassword({ t: "Password updated.", ok: true });
    },
    onError: (err: any) =>
      setMsgPassword({
        t: err?.response?.data?.error?.message || err?.response?.data?.detail || "Password change failed.",
        ok: false,
      }),
  });

  /* ── mfa / notify (device-local) ── */
  const [settings, setSettings] = useState(readSet);
  const [msgMfa, setMsgMfa] = useState<{ t: string; ok: boolean } | null>(null);
  const saveSet = (next: typeof settings) => {
    setSettings(next);
    try {
      localStorage.setItem(SET_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  };

  /* ── status ── */
  const planKey = useMemo(() => {
    try {
      return localStorage.getItem("cerberus_plan") || "";
    } catch {
      return "";
    }
  }, []);
  const verified = user?.status === "verified";

  const setMsg = (setter: typeof setMsgPersonal) => (t: string, ok: boolean) => {
    setter({ t, ok });
    window.setTimeout(() => setter(null), 4000);
  };

  return (
    <main className="main set-main">
      <div className="topbar">
        <div className="crumb">
          <small>Account</small>
          <h1>Settings</h1>
        </div>
      </div>

      <div className="set-layout">
        <nav className="set-nav" aria-label="Settings sections">
          <a href="#personal">Personal info</a>
          <a href="#photo">Profile picture</a>
          <a href="#password">Password</a>
          <a href="#mfa">Two-factor</a>
          <a href="#notify">Notifications</a>
          <a href="#sessions">Sessions</a>
          <a href="#activity">Login activity</a>
          <a href="#status">Account status</a>
        </nav>

        <div className="set-body">
          {/* ── personal ── */}
          <section className="set-card" id="personal">
            <h2 className="set-h">
              <i className="fas fa-id-card" />
              Personal information
            </h2>
            <p className="set-p">Your contact details. They appear on your account and on the reports you receive.</p>
            <form
              className="set-form"
              noValidate
              onSubmit={(e) => {
                e.preventDefault();
                // Client-side validation (the backend re-checks everything).
                const nameErr = checkFullName(personal.full_name);
                if (nameErr) return setMsg(setMsgPersonal)(nameErr, false);
                const titleErr = checkJobTitle(personal.job_title);
                if (titleErr) return setMsg(setMsgPersonal)(titleErr, false);
                const companyErr = checkCompanyName(personal.company_name);
                if (companyErr) return setMsg(setMsgPersonal)(companyErr, false);
                const phoneErr = checkPhone(personal.phone_number ?? "", true);
                if (phoneErr) return setMsg(setMsgPersonal)(phoneErr, false);
                savePersonal.mutate({
                  full_name: personal.full_name.trim(),
                  job_title: personal.job_title.trim(),
                  company_name: personal.company_name.trim(),
                  phone_number: (personal.phone_number ?? "").trim() || null,
                });
              }}
            >
              <div className="set-grid">
                <label className="set-field">
                  <span>Full name</span>
                  <input type="text" autoComplete="name" required maxLength={100} value={personal.full_name} onChange={(e) => setPersonal((p) => ({ ...p, full_name: e.target.value }))} />
                </label>
                <label className="set-field">
                  <span>Job title</span>
                  <input type="text" autoComplete="organization-title" maxLength={60} value={personal.job_title} onChange={(e) => setPersonal((p) => ({ ...p, job_title: e.target.value }))} />
                </label>
                <label className="set-field">
                  <span>Organization</span>
                  <input type="text" autoComplete="organization" maxLength={100} value={personal.company_name} onChange={(e) => setPersonal((p) => ({ ...p, company_name: e.target.value }))} />
                </label>
                <label className="set-field">
                  <span>Phone number</span>
                  <input type="tel" autoComplete="tel" maxLength={20} placeholder="+20 100 000 0000" value={personal.phone_number ?? ""} onChange={(e) => setPersonal((p) => ({ ...p, phone_number: e.target.value }))} />
                </label>
                <label className="set-field full">
                  <span>Email (registered)</span>
                  <input type="email" readOnly value={user?.email || ""} />
                </label>
              </div>
              <div className="set-actions">
                <button type="submit" className="set-btn primary" disabled={savePersonal.isPending}>
                  {savePersonal.isPending ? "Saving…" : "Save changes"}
                </button>
                {msgPersonal && <span className={`set-msg ${msgPersonal.ok ? "ok" : "err"}`}>{msgPersonal.t}</span>}
              </div>
            </form>
          </section>

          {/* ── photo ── */}
          <section className="set-card" id="photo">
            <h2 className="set-h">
              <i className="fas fa-image" />
              Profile picture
            </h2>
            <p className="set-p">Your own photo. Accepted formats: JPG, SVG, PNG, HEIC.</p>
            <div className="set-photo">
              <div className="set-av" id="photoPrev">
                {photo ? <img src={photo} alt="" style={{ width: "100%", height: "100%", objectFit: "cover", borderRadius: "50%" }} /> : (user?.full_name?.[0]?.toUpperCase() || "J")}
              </div>
              <div className="set-actions" style={{ marginTop: 0 }}>
                <label className="set-btn" style={{ display: "inline-flex", alignItems: "center", cursor: "pointer" }}>
                  <i className="fas fa-arrow-up-from-bracket" style={{ marginRight: 8 }} />
                  Upload photo
                  <input
                    ref={fileRef}
                    type="file"
                    accept=".jpg,.jpeg,.png,.svg,.heic,image/jpeg,image/png,image/svg+xml,image/heic"
                    hidden
                    onChange={(e) => {
                      onPhoto(e.target.files?.[0]);
                      e.target.value = "";
                    }}
                  />
                </label>
                <button type="button" className="set-btn" id="photoRemove" disabled={!photo} onClick={removePhoto}>
                  Remove
                </button>
              </div>
            </div>
            {msgPhoto && <span className={`set-msg ${msgPhoto.ok ? "ok" : "err"}`}>{msgPhoto.t}</span>}
          </section>

          {/* ── password ── */}
          <section className="set-card" id="password">
            <h2 className="set-h">
              <i className="fas fa-key" />
              Password
            </h2>
            <p className="set-p">Use at least 8 characters. Passwords are never stored in this browser.</p>
            <form
              className="set-form"
              noValidate
              onSubmit={(e) => {
                e.preventDefault();
                if (!pw.cur) return setMsg(setMsgPassword)("Enter your current password.", false);
                const pwErr = checkPassword(pw.new1);
                if (pwErr) return setMsg(setMsgPassword)(pwErr, false);
                const matchErr = checkPasswordMatch(pw.new1, pw.new2);
                if (matchErr) return setMsg(setMsgPassword)(matchErr, false);
                changePw.mutate();
              }}
            >
              <div className="set-grid">
                <label className="set-field full">
                  <span>Current password</span>
                  <input type="password" autoComplete="current-password" maxLength={128} value={pw.cur} onChange={(e) => setPw((p) => ({ ...p, cur: e.target.value }))} />
                </label>
                <label className="set-field">
                  <span>New password</span>
                  <input type="password" autoComplete="new-password" minLength={8} maxLength={128} value={pw.new1} onChange={(e) => setPw((p) => ({ ...p, new1: e.target.value }))} />
                </label>
                <label className="set-field">
                  <span>Confirm new password</span>
                  <input type="password" autoComplete="new-password" minLength={8} maxLength={128} value={pw.new2} onChange={(e) => setPw((p) => ({ ...p, new2: e.target.value }))} />
                </label>
              </div>
              <div className="set-actions">
                <button type="submit" className="set-btn primary" disabled={changePw.isPending}>
                  {changePw.isPending ? "Updating…" : "Update password"}
                </button>
                {msgPassword && <span className={`set-msg ${msgPassword.ok ? "ok" : "err"}`}>{msgPassword.t}</span>}
              </div>
            </form>
          </section>

          {/* ── mfa ── */}
          <section className="set-card" id="mfa">
            <h2 className="set-h">
              <i className="fas fa-shield-halved" />
              Two-factor authentication
            </h2>
            <div className="set-row">
              <div>
                <b>Require a code at sign-in</b>
                <small>We send a 6-digit code to your email each time you log in.</small>
              </div>
              <label className="sw">
                <input
                  type="checkbox"
                  checked={settings.mfa}
                  onChange={(e) => {
                    saveSet({ ...settings, mfa: e.target.checked });
                    setMsg(setMsgMfa)(e.target.checked ? "Codes will be required at sign-in." : "Codes are no longer required at sign-in.", true);
                  }}
                />
                <span></span>
              </label>
            </div>
            {msgMfa && <span className={`set-msg ${msgMfa.ok ? "ok" : "err"}`}>{msgMfa.t}</span>}
            {!user?.mfa_enabled && <p className="set-p" style={{ marginTop: 8 }}>Stored on this device — the server-side MFA endpoint is pending.</p>}
          </section>

          {/* ── notify ── */}
          <section className="set-card" id="notify">
            <h2 className="set-h">
              <i className="fas fa-bell" />
              Notification preferences
            </h2>
            <p className="set-p">Choose where each kind of update reaches you.</p>
            <div className="set-notify-head">
              <span>Update</span>
              <span>Email</span>
              <span>In app</span>
            </div>
            <div id="notifyRows">
              {CATS.map((c) => (
                <div className="set-notify-row" key={c.id}>
                  <div>
                    <b>{c.label}</b>
                    <small>{c.desc}</small>
                  </div>
                  <label className="sw" style={{ margin: "0 auto" }}>
                    <input
                      type="checkbox"
                      checked={settings.notify.email[c.id]}
                      onChange={(e) => saveSet({ ...settings, notify: { ...settings.notify, email: { ...settings.notify.email, [c.id]: e.target.checked } } })}
                    />
                    <span></span>
                  </label>
                  <label className="sw" style={{ margin: "0 auto" }}>
                    <input
                      type="checkbox"
                      checked={settings.notify.app[c.id]}
                      onChange={(e) => saveSet({ ...settings, notify: { ...settings.notify, app: { ...settings.notify.app, [c.id]: e.target.checked } } })}
                    />
                    <span></span>
                  </label>
                </div>
              ))}
            </div>
            <div className="set-notify-row">
              <div>
                <b>Security alerts</b>
                <small>Always on. Sent for suspicious sign-ins and account changes.</small>
              </div>
              <label className="sw" style={{ margin: "0 auto" }}>
                <input type="checkbox" checked disabled />
                <span></span>
              </label>
              <label className="sw" style={{ margin: "0 auto" }}>
                <input type="checkbox" checked disabled />
                <span></span>
              </label>
            </div>
          </section>

          {/* ── sessions ── */}
          <section className="set-card" id="sessions">
            <h2 className="set-h">
              <i className="fas fa-laptop" />
              Active sessions
            </h2>
            <p className="set-p">Devices currently signed in to your account.</p>
            <div id="sessList">
              <div className="set-row">
                <div>
                  <b>{deviceName()}</b>
                  <small>This device · Active now</small>
                </div>
                <span className="pill on">Current</span>
              </div>
            </div>
            <div className="set-actions">
              <button type="button" className="set-btn" id="signOutOthers" disabled title="Server-side session tracking is pending">
                Sign out other sessions
              </button>
            </div>
          </section>

          {/* ── activity ── */}
          <section className="set-card" id="activity">
            <h2 className="set-h">
              <i className="fas fa-clock-rotate-left" />
              Recent login activity
            </h2>
            <p className="set-p">Sign-ins to your account, with the device and location. Report anything you do not recognise.</p>
            <div className="set-empty">No sign-ins recorded yet.</div>
          </section>

          {/* ── status ── */}
          <section className="set-card" id="status">
            <h2 className="set-h">
              <i className="fas fa-user-check" />
              Account status
            </h2>
            <div className="set-row">
              <div>
                <b>Email verification</b>
                <small>{verified ? "Verified with a one-time code." : "Enter the code we sent to your email to finish setup."}</small>
              </div>
              <span className="pill" id="stVerified">{verified ? "Verified" : "Pending"}</span>
            </div>
            <div className="set-row">
              <div>
                <b>Plan</b>
                <small>Your current subscription.</small>
              </div>
              <span className="pill" id="stPlan">{planKey || "Free"}</span>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
