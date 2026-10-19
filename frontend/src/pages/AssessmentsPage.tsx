/**
 * Assessments Page — ported from the new front-end's assessments.html,
 * rewired from localStorage to GET /engagements (real list endpoint).
 *
 * Row mapping (backend EngagementResponse → mock Assessment row):
 *   target  = project_name        client = organization_name
 *   started = started_at ?? created_at
 *   status  = status              risk   = risk_level
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import UserChip from "../components/layout/UserChip";
import { engagementApi } from "../api/engagementApi";
import { formatDate } from "../utils/formatters";
import type { Engagement } from "../types";

const cap = (s?: string | null) => (s ? s.replace(/_/g, " ") : "—");

export default function AssessmentsPage() {
  const [q, setQ] = useState("");
  const { data, isLoading } = useQuery({
    queryKey: ["engagements", "list"],
    queryFn: async () => (await engagementApi.list({ page: 1, page_size: 200 })).data,
  });

  const rows: Engagement[] = data?.items ?? [];
  const filtered = rows.filter(
    (r) => !q || `${r.project_name} ${r.organization_name}`.toLowerCase().includes(q.toLowerCase())
  );

  return (
    <main className="main">
      <div className="topbar">
        <div className="crumb">
          <small>Your engagements</small>
          <h1>Assessments</h1>
        </div>
        <UserChip />
      </div>

      <div className="panel">
        {rows.length === 0 && (
          <div className="empty-state">
            <div className="empty-ico">
              <i className="fas fa-clipboard-list" />
            </div>
            <h3>No assessments yet</h3>
            <p>Start an assessment from AI Chat. Every engagement you run will be listed here with its target, client, and status.</p>
          </div>
        )}

        {rows.length > 0 && (
          <div className="panel-tools">
            <div className="search-box">
              <i className="fas fa-magnifying-glass" />
              <input type="search" placeholder="Search target or client" aria-label="Search assessments" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
          </div>
        )}

        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Client</th>
                  <th>Started</th>
                  <th>Status</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id}>
                    <td>{r.project_name}</td>
                    <td>{r.organization_name}</td>
                    <td>{formatDate(r.started_at || r.created_at)}</td>
                    <td>{cap(r.status)}</td>
                    <td>{r.risk_level ? cap(r.risk_level) : "—"}</td>
                  </tr>
                ))}
                {!isLoading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                      No matches for “{q}”.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </main>
  );
}
