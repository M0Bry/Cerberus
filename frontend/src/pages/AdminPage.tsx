/**
 * Admin Page — ported from the new front-end's admin.html + js/admin.js,
 * rewired to the real admin endpoints:
 *
 *   GET /admin/dashboard   → {total_users, active_users, total_engagements, active_engagements, total_reports, system_health}
 *   GET /admin/users       → {total, items: AdminUserItem[]}
 *   GET /admin/audit-logs  → {total, items: AuditLogItem[]}
 *   GET /engagements       → engagements list (no /admin/engagements endpoint exists)
 *   GET /health            → {status, version}  (API root, not /api/v1)
 *
 * Contact Messages: the landing form POSTs to /public/contact, which returns
 * success but persists nothing (backend gap) → this view is an explicit empty
 * state explaining that.
 *
 * The mock's Roles / Alerts / Billing sections had no backend endpoints and
 * were dropped from scope (see CHANGE_LIST.md).
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { adminApi } from "../api/adminApi";
import { engagementApi } from "../api/engagementApi";
import { useAuthStore } from "../store/useAuthStore";
import { formatDate, formatDateTime } from "../utils/formatters";
import type { AdminAuditEntry, AdminUserRow, Engagement } from "../types";

const VIEWS = ["users", "engagements", "system", "audit", "messages"] as const;
type View = (typeof VIEWS)[number];

const cap = (s?: string | null) => (s ? s.replace(/_/g, " ") : "—");

/** "Plan" column — the account's effective access state. */
function renderPlanCell(u: AdminUserRow) {
  const state = u.access_state ?? (u.plan_name ? "paid" : "trial");
  if (state === "paid") {
    return (
      <span style={{ color: "#4ade80", fontWeight: 600 }}>
        {u.plan_name || "Subscribed"}
      </span>
    );
  }
  if (state === "suspended") {
    return (
      <span style={{ color: "#f87171", fontWeight: 600 }}>
        <i className="fas fa-lock" /> Suspended
      </span>
    );
  }
  const days = u.trial_days_left ?? 0;
  return (
    <span style={{ color: "#60a5fa" }}>
      Free trial{days > 0 ? ` · ${days}d left` : ""}
    </span>
  );
}

export default function AdminPage() {
  const user = useAuthStore((s) => s.user);
  const [view, setView] = useState<View>("users");
  const [uSearch, setUSearch] = useState("");
  const [engSearch, setEngSearch] = useState("");
  const [auditSearch, setAuditSearch] = useState("");
  const [auditResult, setAuditResult] = useState("all");
  const [healthState, setHealthState] = useState<{ ok: boolean; text: string } | null>(null);

  /* contact inbox state */
  const [msgUnreadOnly, setMsgUnreadOnly] = useState(false);
  const [msgExpanded, setMsgExpanded] = useState<string | null>(null);
  const [msgReplyId, setMsgReplyId] = useState<string | null>(null);
  const [msgReplyText, setMsgReplyText] = useState("");
  const [msgReplyNote, setMsgReplyNote] = useState<{ id: string; text: string; ok: boolean } | null>(null);

  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();

  /* ── contact inbox (admin sees every landing-form submission) ── */
  const contacts = useQuery({
    queryKey: ["admin", "contacts", msgUnreadOnly],
    queryFn: async () =>
      (await adminApi.getContactMessages({ page: 1, page_size: 100, unread_only: msgUnreadOnly })).data,
    enabled: isAdmin,
  });
  const msgRows = contacts.data?.items ?? [];
  const msgUnread = contacts.data?.unread ?? 0;

  const markMsgRead = useMutation({
    mutationFn: (id: string) => adminApi.markContactRead(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "contacts"] }),
  });

  const sendReply = useMutation({
    mutationFn: ({ id, message }: { id: string; message: string }) => adminApi.replyContact(id, message),
    onSuccess: (res, vars) => {
      const data = res.data;
      setMsgReplyNote({
        id: vars.id,
        ok: true,
        text:
          data.delivery === "notification"
            ? "Reply sent — the sender will see it on their Notifications page."
            : data.delivery === "email"
              ? "Reply sent — emailed to the address they provided."
              : `Reply saved. ${data.delivery_note ?? ""}`.trim(),
      });
      setMsgReplyId(null);
      setMsgReplyText("");
      queryClient.invalidateQueries({ queryKey: ["admin", "contacts"] });
    },
    onError: (err: any, vars) => {
      setMsgReplyNote({
        id: vars.id,
        ok: false,
        text: `Could not send reply: ${err?.response?.data?.detail || "unknown error"}`,
      });
    },
  });

  /* ── data ── */
  const dash = useQuery({
    queryKey: ["admin", "dashboard"],
    queryFn: async () => (await adminApi.getDashboard()).data as {
      total_users: number;
      active_users: number;
      total_engagements: number;
      active_engagements: number;
      total_reports: number;
      system_health: string;
    },
    enabled: isAdmin,
  });

  const users = useQuery({
    queryKey: ["admin", "users", uSearch],
    queryFn: async () => (await adminApi.getUsers({ page: 1, page_size: 200, search: uSearch || undefined })).data as {
      total: number;
      items: AdminUserRow[];
    },
    enabled: isAdmin && view === "users",
    placeholderData: (prev) => prev,
  });

  const engs = useQuery({
    queryKey: ["admin", "engagements"],
    queryFn: async () => (await engagementApi.list({ page: 1, page_size: 200 })).data,
    enabled: isAdmin && view === "engagements",
  });

  const audit = useQuery({
    queryKey: ["admin", "audit-logs"],
    queryFn: async () => (await adminApi.getAuditLogs({ page: 1, page_size: 200 })).data as {
      total: number;
      items: AdminAuditEntry[];
    },
    enabled: isAdmin && view === "audit",
  });

  const checkHealth = async () => {
    setHealthState({ ok: false, text: "Checking…" });
    try {
      const res = await fetch("/health");
      const data: any = await res.json();
      setHealthState({
        ok: res.ok,
        text: res.ok ? `Backend reachable — v${data.version || "unknown"}` : `Backend responded ${res.status}`,
      });
    } catch {
      setHealthState({ ok: false, text: "Backend unreachable from this origin." });
    }
  };

  /* ── denied state (non-admin roles) ── */
  if (!isAdmin) {
    return (
      <main className="main admin-main">
        <div className="topbar">
          <div className="crumb">
            <small>Administration</small>
            <h1>Admin Dashboard</h1>
          </div>
          <Link className="admin-back" to="/chat">
            <i className="fas fa-arrow-left" /> Back to app
          </Link>
        </div>
        <div className="adm-denied">
          <div className="empty-ico">
            <i className="fas fa-lock" />
          </div>
          <h3>Admin access only</h3>
          <p>
            Your role is <b>{cap(user?.role) || "User"}</b>. This area needs a role with admin permissions.
          </p>
          <Link className="admin-back" to="/chat">
            <i className="fas fa-arrow-left" /> Back to app
          </Link>
        </div>
      </main>
    );
  }

  const userRows = (users.data?.items ?? []).filter(
    (u) => !uSearch || `${u.full_name} ${u.email}`.toLowerCase().includes(uSearch.toLowerCase())
  );
  const engRows: Engagement[] = (engs.data?.items ?? []).filter(
    (e) => !engSearch || `${e.project_name} ${e.organization_name}`.toLowerCase().includes(engSearch.toLowerCase())
  );
  const auditRows = (audit.data?.items ?? []).filter((a) => {
    const q = auditSearch.toLowerCase();
    const hit = !q || `${a.user_id || "system"} ${a.action} ${a.severity} ${a.description}`.toLowerCase().includes(q);
    const sev = (a.severity || "").toLowerCase();
    const isFailed = sev === "critical" || sev === "error";
    const resOk = auditResult === "all" || (auditResult === "Failed" ? isFailed : !isFailed);
    return hit && resOk;
  });

  return (
    <main className="main admin-main">
      <div className="topbar">
        <div className="crumb">
          <small>Administration</small>
          <h1>Admin Dashboard</h1>
        </div>
        <Link className="admin-back" to="/chat">
          <i className="fas fa-arrow-left" /> Back to app
        </Link>
      </div>

      <section className="kpis" aria-label="Key figures">
        <div className="kpi">
          <span className="kpi-l">
            <i className="fas fa-users" />
            Users
          </span>
          <b>{dash.data?.total_users ?? "—"}</b>
          <small>{dash.data ? `${dash.data.active_users} active` : "No accounts yet"}</small>
        </div>
        <div className="kpi">
          <span className="kpi-l">
            <i className="fas fa-list-check" />
            Running
          </span>
          <b>{dash.data?.active_engagements ?? "—"}</b>
          <small>{dash.data ? `${dash.data.total_engagements} total` : "None run yet"}</small>
        </div>
        <div className="kpi">
          <span className="kpi-l">
            <i className="fas fa-file-shield" />
            Reports
          </span>
          <b>{dash.data?.total_reports ?? "—"}</b>
          <small>{dash.data ? "generated so far" : "None yet"}</small>
        </div>
        <div className="kpi">
          <span className="kpi-l">
            <i className="fas fa-heart-pulse" />
            System
          </span>
          <b>{dash.data?.system_health ? cap(dash.data.system_health) : "—"}</b>
          <small>platform-wide status</small>
        </div>
      </section>

      <div className="adm-layout">
        <nav className="adm-nav" aria-label="Admin sections">
          {(
            [
              ["users", "User Management"],
              ["engagements", "Engagements"],
              ["system", "System Health"],
              ["audit", "Audit Logs"],
              ["messages", "Contact Messages"],
            ] as [View, string][]
          ).map(([v, label]) => (
            <a key={v} href={`#${v}`} className={view === v ? "active" : ""} onClick={() => setView(v)}>
              {label}
            </a>
          ))}
        </nav>

        <div className="adm-body">
          {/* ── users ── */}
          <section className="adm-view" id="users" hidden={view !== "users"}>
            <div className="adm-tools">
              <div className="search-box">
                <i className="fas fa-magnifying-glass" />
                <input type="search" placeholder="Search name or email" aria-label="Search users" value={uSearch} onChange={(e) => setUSearch(e.target.value)} />
              </div>
            </div>
            {userRows.length === 0 && (
              <div className="empty-state">
                <div className="empty-ico">
                  <i className="fas fa-user-plus" />
                </div>
                <h3>No users yet</h3>
                <p>Accounts appear here once people register and verify their email.</p>
              </div>
            )}
            {userRows.length > 0 && (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Verification</th>
                      <th>Plan</th>
                      <th>Joined</th>
                    </tr>
                  </thead>
                  <tbody>
                    {userRows.map((u) => (
                      <tr key={u.id}>
                        <td>{u.full_name}</td>
                        <td>{u.email}</td>
                        <td>{cap(u.role)}</td>
                        <td>{cap(u.status)}</td>
                        <td>{u.status === "verified" ? "Verified" : "—"}</td>
                        <td>{renderPlanCell(u)}</td>
                        <td>{formatDate(u.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="adm-note">A disabled account is flagged here. Blocking its sign-in needs the back end.</p>
          </section>

          {/* ── engagements ── */}
          <section className="adm-view" id="engagements" hidden={view !== "engagements"}>
            <div className="adm-tools">
              <div className="search-box">
                <i className="fas fa-magnifying-glass" />
                <input type="search" placeholder="Search target or client" aria-label="Search engagements" value={engSearch} onChange={(e) => setEngSearch(e.target.value)} />
              </div>
            </div>
            {engRows.length === 0 && (
              <div className="empty-state">
                <div className="empty-ico">
                  <i className="fas fa-shield-halved" />
                </div>
                <h3>No engagements yet</h3>
                <p>Every Security Assessment appears here once an assessment is started from AI Chat.</p>
              </div>
            )}
            {engRows.length > 0 && (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Client</th>
                      <th>Started</th>
                      <th>Status</th>
                      <th>Risk</th>
                      <th>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {engRows.map((e) => (
                      <tr key={e.id}>
                        <td>{e.project_name}</td>
                        <td>{e.organization_name}</td>
                        <td>{formatDate(e.started_at || e.created_at)}</td>
                        <td>{cap(e.status)}</td>
                        <td>{e.risk_level ? cap(e.risk_level) : "—"}</td>
                        <td>{e.overall_security_score ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* ── system health ── */}
          <section className="adm-view" id="system" hidden={view !== "system"}>
            <div className="adm-tools">
              <button type="button" className="msg-btn primary" onClick={checkHealth}>
                <i className="fas fa-rotate" /> Check now
              </button>
              {healthState && <span className={`adm-msg ${healthState.ok ? "ok" : "err"}`}>{healthState.text}</span>}
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>API backend</td>
                    <td>
                      <span className="pill">{healthState ? (healthState.ok ? "Reachable" : "Unreachable") : "Not checked"}</span>
                    </td>
                    <td>GET /health</td>
                  </tr>
                  <tr>
                    <td>CPU and memory</td>
                    <td>
                      <span className="pill">Not reported</span>
                    </td>
                    <td>Needs a metrics endpoint on the back end.</td>
                  </tr>
                  <tr>
                    <td>Errors (last 24h)</td>
                    <td>
                      <span className="pill">Not reported</span>
                    </td>
                    <td>Needs an error log endpoint on the back end.</td>
                  </tr>
                  <tr>
                    <td>Queued background tasks</td>
                    <td>
                      <span className="pill">Not reported</span>
                    </td>
                    <td>Needs a Celery queue report from the back end.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* ── audit logs ── */}
          <section className="adm-view" id="audit" hidden={view !== "audit"}>
            <div className="adm-tools">
              <div className="search-box">
                <i className="fas fa-magnifying-glass" />
                <input type="search" placeholder="Search actor, action or detail" aria-label="Search audit log" value={auditSearch} onChange={(e) => setAuditSearch(e.target.value)} />
              </div>
              <select className="adm-sel-lg" aria-label="Filter by result" value={auditResult} onChange={(e) => setAuditResult(e.target.value)}>
                <option value="all">All results</option>
                <option value="Success">Success</option>
                <option value="Failed">Failed</option>
              </select>
            </div>
            {auditRows.length === 0 && (
              <div className="empty-state">
                <div className="empty-ico">
                  <i className="fas fa-clock-rotate-left" />
                </div>
                <h3>No activity yet</h3>
                <p>Sign-ins, profile and permission changes, and admin actions are logged here with who did them and when.</p>
              </div>
            )}
            {auditRows.length > 0 && (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Detail</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditRows.map((a) => (
                      <tr key={a.id}>
                        <td>
                          {(() => {
                            const iso = a.created_at || a.timestamp || "";
                            return iso && !isNaN(new Date(iso).getTime()) ? formatDateTime(iso) : "—";
                          })()}
                        </td>
                        <td>{a.user_id ? String(a.user_id).slice(0, 8) : "system"}</td>
                        <td>{cap(a.action)}</td>
                        <td>{a.description || "—"}</td>
                        <td>{cap(a.severity)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* ── contact messages (admin inbox) ── */}
          <section className="adm-view" id="messages" hidden={view !== "messages"}>
            <div className="adm-tools" style={{ display: "flex", alignItems: "center", gap: 18 }}>
              <label
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 8,
                  fontSize: 13,
                  color: "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                <input type="checkbox" checked={msgUnreadOnly} onChange={(e) => setMsgUnreadOnly(e.target.checked)} />
                Unread only
                {msgUnread > 0 && (
                  <b style={{ color: "var(--accent)" }}>({msgUnread})</b>
                )}
              </label>
              <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                {msgRows.length} shown · {contacts.data?.total ?? 0} total
              </span>
            </div>

            {msgRows.length === 0 && !contacts.isLoading && (
              <div className="empty-state">
                <div className="empty-ico">
                  <i className="fas fa-envelope-open-text" />
                </div>
                <h3>{msgUnreadOnly ? "No unread messages" : "No messages yet"}</h3>
                <p>
                  {msgUnreadOnly
                    ? "Everything in the inbox has been read. Switch off “Unread only” to see the full history."
                    : "Messages sent from the Contact form on the landing page land here. Registered senders are linked to their account automatically."}
                </p>
              </div>
            )}

            {msgRows.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {msgRows.map((m) => (
                  <div
                    key={m.id}
                    style={{ border: "1px solid var(--border-strong)", borderRadius: 10, background: "rgba(255,255,255,.02)" }}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setMsgExpanded(msgExpanded === m.id ? null : m.id);
                        if (!m.is_read) markMsgRead.mutate(m.id);
                      }}
                      style={{
                        width: "100%",
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        padding: "12px 16px",
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        color: "var(--text-primary)",
                        textAlign: "left",
                      }}
                    >
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: 999,
                          background: m.is_read ? "transparent" : "var(--accent)",
                          border: m.is_read ? "1px solid var(--border-strong)" : "none",
                          flex: "0 0 8px",
                        }}
                      />
                      <span style={{ fontFamily: "var(--font-display)", letterSpacing: 0.5, fontSize: 14 }}>
                        {m.subject}
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          color: m.registered ? "#4ade80" : "var(--text-muted)",
                          border: `1px solid ${m.registered ? "rgba(74,222,128,.4)" : "var(--border-strong)"}`,
                          borderRadius: 999,
                          padding: "2px 8px",
                          letterSpacing: 1,
                        }}
                      >
                        {m.registered ? "REGISTERED" : "UNREGISTERED"}
                      </span>
                      <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                        {formatDateTime(m.created_at)}
                      </span>
                    </button>

                    {msgExpanded === m.id && (
                      <div style={{ padding: "0 16px 14px" }}>
                        <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 10 }}>
                          {m.name} · {m.email}
                          {m.ip_address ? ` · ${m.ip_address}` : ""}{" "}
                          <span style={{ color: "var(--text-muted)" }}>
                            ({m.registered ? "linked to their account" : "no account — reply goes to their email"})
                          </span>
                        </div>
                        <p
                          style={{
                            fontSize: 14,
                            color: "var(--text-primary)",
                            lineHeight: 1.55,
                            margin: "0 0 12px",
                            whiteSpace: "pre-wrap",
                          }}
                        >
                          {m.message}
                        </p>

                        {m.reply && (
                          <div
                            style={{
                              borderLeft: "2px solid var(--accent)",
                              padding: "6px 12px",
                              marginBottom: 12,
                              fontSize: 13,
                              color: "var(--text-secondary)",
                            }}
                          >
                            <b style={{ color: "var(--text-primary)" }}>
                              Your reply{m.replied_at ? ` · ${formatDateTime(m.replied_at)}` : ""}:
                            </b>{" "}
                            {m.reply}
                          </div>
                        )}

                        {msgReplyId === m.id && (
                          <div>
                            <textarea
                              value={msgReplyText}
                              onChange={(e) => setMsgReplyText(e.target.value)}
                              rows={4}
                              placeholder="Write your reply (5–5000 characters)…"
                              style={{
                                width: "100%",
                                background: "rgba(0,0,0,.25)",
                                border: "1px solid var(--border-strong)",
                                borderRadius: 8,
                                color: "var(--text-primary)",
                                padding: 10,
                                fontSize: 13,
                                resize: "vertical",
                              }}
                            />
                            <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
                              <button
                                className="btn btn-primary"
                                disabled={sendReply.isPending || msgReplyText.trim().length < 5}
                                onClick={() => sendReply.mutate({ id: m.id, message: msgReplyText.trim() })}
                              >
                                {sendReply.isPending ? "Sending…" : "Send reply"}
                              </button>
                              <button
                                className="btn btn-ghost"
                                onClick={() => {
                                  setMsgReplyId(null);
                                  setMsgReplyText("");
                                  setMsgReplyNote(null);
                                }}
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        )}

                        {msgReplyId !== m.id && !m.reply && (
                          <button
                            className="btn btn-outline"
                            onClick={() => {
                              setMsgReplyId(m.id);
                              setMsgReplyNote(null);
                            }}
                          >
                            <i className="fas fa-reply" /> Reply
                          </button>
                        )}

                        {msgReplyNote?.id === m.id && (
                          <p
                            style={{
                              fontSize: 13,
                              color: msgReplyNote.ok ? "#4ade80" : "#f87171",
                              marginTop: 10,
                              marginBottom: 0,
                            }}
                          >
                            <i className={`fas ${msgReplyNote.ok ? "fa-circle-check" : "fa-triangle-exclamation"}`} />{" "}
                            {msgReplyNote.text}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            <p className="adm-note">
              Replies to registered senders appear on their Notifications page; unregistered (guest) senders receive the
              reply by email at the address they typed.
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
