/**
 * API Test Page (dev bench) — ported from the new front-end's api.html + js/api.js.
 *
 * Mounted at /dev/api. Gated out of production builds: in production it
 * renders a 404 panel instead of the bench.
 *
 * One request per endpoint; bodies match the backend schemas. The Server URL
 * defaults to the local backend (http://localhost:8000) and the optional Bearer
 * token is applied to every request.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import NotFoundPage from "../components/errors/NotFoundPage";

const ENDPOINTS: { method: string; path: string; desc: string; body?: unknown; note?: string }[] = [
  { method: "GET", path: "/health", desc: "Liveness check. Returns status and version.", body: null },
  {
    method: "POST",
    path: "/api/v1/auth/register",
    desc: "Create a user account. Sends a verification code to the email.",
    body: {
      full_name: "Mariam Ali",
      company_name: "Acme Corp",
      job_title: "CISO",
      email: "user@example.com",
      phone_number: "+20 100 000 0000",
      password: "ChangeMe#2026",
      confirm_password: "ChangeMe#2026",
    },
    note: "company_location is optional on the back end and is not sent by the form.",
  },
  {
    method: "POST",
    path: "/api/v1/auth/verify-otp",
    desc: "Verify the email with the 6-digit code and activate the account.",
    body: { email: "user@example.com", otp: "123456" },
  },
  { method: "POST", path: "/api/v1/auth/resend-otp", desc: "Send a new verification code. Enforces a cooldown.", body: { email: "user@example.com" } },
  {
    method: "POST",
    path: "/api/v1/auth/login",
    desc: "Log in. Returns access and refresh tokens. Unverified accounts are rejected.",
    body: { email: "user@example.com", password: "ChangeMe#2026" },
  },
  { method: "POST", path: "/api/v1/auth/refresh", desc: "Exchange a refresh token for a new access token.", body: { refresh_token: "paste-refresh-token" } },
  { method: "POST", path: "/api/v1/auth/logout", desc: "End the current session. Uses the access token above.", body: null },
];

interface Resp {
  kind: "" | "ok" | "err" | "warn";
  text: string;
}

export default function ApiTestPage() {
  const [base, setBase] = useState("http://localhost:8000");
  const [token, setToken] = useState("");
  const [bodies, setBodies] = useState<string[]>(() => ENDPOINTS.map((e) => (e.body ? JSON.stringify(e.body, null, 2) : "")));
  const [resps, setResps] = useState<Resp[]>(() => ENDPOINTS.map(() => ({ kind: "", text: "" })));
  const [busy, setBusy] = useState<boolean[]>(() => ENDPOINTS.map(() => false));

  if (!import.meta.env.DEV) {
    return <NotFoundPage />;
  }

  const setResp = (i: number, kind: Resp["kind"], text: string) =>
    setResps((prev) => prev.map((r, j) => (j === i ? { kind, text } : r)));

  const send = async (i: number) => {
    const ep = ENDPOINTS[i];
    const origin = base.trim().replace(/\/+$/, "");
    const url = origin + ep.path;
    let body: string | undefined;
    if (ep.body !== null) {
      const raw = bodies[i].trim();
      if (raw) {
        try {
          body = JSON.stringify(JSON.parse(raw));
        } catch {
          return setResp(i, "err", "Request body is not valid JSON.");
        }
      }
    }
    const headers: Record<string, string> = {};
    if (body) headers["Content-Type"] = "application/json";
    if (token.trim()) headers["Authorization"] = `Bearer ${token.trim()}`;

    setBusy((prev) => prev.map((b, j) => (j === i ? true : b)));
    setResp(i, "", `${ep.method} ${url} …`);
    try {
      const res = await fetch(url, { method: ep.method, headers, body });
      const txt = await res.text();
      if ([404, 405, 501].includes(res.status)) {
        setResp(i, "warn", `Not reachable: ${ep.path} returned HTTP ${res.status}. Check the server URL and that the back end is running.`);
      } else {
        let pretty = txt;
        try {
          pretty = JSON.stringify(JSON.parse(txt), null, 2);
        } catch {
          /* not JSON */
        }
        setResp(i, res.ok ? "ok" : "err", `HTTP ${res.status} ${res.statusText}\n${pretty || "(empty body)"}`);
      }
    } catch {
      setResp(i, "warn", `No response from ${origin || "this server"}. Start the back end (uvicorn app.main:app) and allow this page's origin in CORS_ORIGINS.`);
    } finally {
      setBusy((prev) => prev.map((b, j) => (j === i ? false : b)));
    }
  };

  return (
    <>
      <header className="api-top">
        <Link to="/chat" className="api-brand">
          <img src="/assets/newfront/logo-cerberus.png" alt="Cerberus" />
        </Link>
        <span className="api-tag">Developer · connection test</span>
      </header>

      <main className="api-wrap">
        <h1 className="api-title">API Test</h1>
        <p className="api-intro">
          Internal check of the link between this front end and the Cerberus back end (FastAPI, <code>/api/v1</code>). For
          developers only. No AI content and no API keys are stored here. Start the back end locally, then run the requests
          below.
        </p>

        <div className="api-fields">
          <label className="api-field">
            <span>Server URL</span>
            <input type="text" value={base} onChange={(e) => setBase(e.target.value)} spellCheck={false} autoComplete="off" />
          </label>
          <label className="api-field">
            <span>Access token (optional, sent as Bearer)</span>
            <input type="text" placeholder="Paste after login" value={token} onChange={(e) => setToken(e.target.value)} spellCheck={false} autoComplete="off" />
          </label>
        </div>

        <div className="api-list">
          {ENDPOINTS.map((ep, i) => (
            <article className="api-card" key={i}>
              <header className="api-head">
                <span className={`api-method ${ep.method.toLowerCase()}`}>{ep.method}</span>
                <code className="api-path">{ep.path}</code>
              </header>
              <p className="api-desc">{ep.desc}</p>
              {ep.note && <p className="api-note">{ep.note}</p>}
              {ep.body !== null && (
                <textarea className="api-body" aria-label="Request body" spellCheck={false} value={bodies[i]} onChange={(e) => setBodies((prev) => prev.map((b, j) => (j === i ? e.target.value : b)))} />
              )}
              <div className="api-actions">
                <button type="button" className="api-send" disabled={busy[i]} onClick={() => void send(i)}>
                  {busy[i] ? "Sending…" : "Send"}
                </button>
              </div>
              {resps[i].text && <div className={`api-resp ${resps[i].kind}`}>{resps[i].text}</div>}
            </article>
          ))}
        </div>
      </main>
    </>
  );
}
