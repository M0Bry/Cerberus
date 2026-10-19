/**
 * Reports Page — ported from the new front-end's reports.html,
 * rewired from localStorage to the real per-engagement report endpoints:
 *
 *   GET /engagements                     (to know which assessments exist)
 *   GET /reports/:engagementId           (reports for that assessment)
 *   GET /reports/:engagementId/:id/download  (PDF bytes)
 *
 * There is no global reports list on the backend, so this page fans out over
 * the user's engagements and flattens the results.
 */
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import UserChip from "../components/layout/UserChip";
import { engagementApi } from "../api/engagementApi";
import { reportApi } from "../api/reportApi";
import { formatDate } from "../utils/formatters";
import type { ReportRow } from "../types";

/** Row = backend ReportItem normalized: engagement_id is always filled (from the
    list wrapper when the item lacks it) so downloads can be scoped correctly. */
interface Row {
  id: string;
  engagement_id: string;
  title: string;
  status?: string;
  created_at?: string;
  generated_at?: string;
  assessment: string;
  [key: string]: unknown;
}

/** Backend ReportItem dates the row "generated_at"; older data may use "created_at". */
function rowDate(r: ReportRow): string {
  return r.generated_at || r.created_at || "";
}

function dateLabel(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "—" : formatDate(iso);
}

export default function ReportsPage() {
  const [downloading, setDownloading] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["engagements", "list"],
    queryFn: async () => (await engagementApi.list({ page: 1, page_size: 200 })).data,
  });
  const engagements = listQuery.data?.items ?? [];

  const reportsQuery = useQuery({
    queryKey: ["reports", "all"],
    queryFn: async (): Promise<Row[]> => {
      const results = await Promise.all(
        engagements.map(async (eng) => {
          try {
            const res = (await reportApi.list(eng.id)).data;
            const items: ReportRow[] = res.items ?? res.reports ?? [];
            // ReportItem carries no engagement_id of its own — it comes from the
            // list wrapper (this engagement), and dates use "generated_at".
            return items.map((r) => ({
              ...r,
              engagement_id: r.engagement_id || eng.id,
              assessment: eng.project_name,
            }));
          } catch {
            return [];
          }
        })
      );
      return results.flat().sort((a, b) => (rowDate(a) < rowDate(b) ? 1 : -1));
    },
    enabled: engagements.length > 0,
    staleTime: 60_000,
  });

  const download = useMutation({
    mutationFn: async ({ engagementId, reportId }: { engagementId: string; reportId: string }) => {
      const res = await reportApi.downloadPdf(engagementId, reportId);
      const blob = new Blob([res.data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cerberus-report-${reportId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },
    onSuccess: () => setDownloading(null),
    onError: () => setDownloading(null),
  });

  const rows: Row[] = reportsQuery.data ?? [];

  return (
    <main className="main">
      <div className="topbar">
        <div className="crumb">
          <small>Documents</small>
          <h1>Reports</h1>
        </div>
        <UserChip />
      </div>

      <div className="panel">
        {rows.length === 0 && (
          <div className="empty-state">
            <div className="empty-ico">
              <i className="fas fa-file-pdf" />
            </div>
            <h3>No reports yet</h3>
            <p>Each completed assessment generates a PDF report. Reports are listed here once an assessment finishes.</p>
          </div>
        )}

        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Assessment</th>
                  <th>Generated</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>{r.title || r.id.slice(0, 8)}</td>
                    <td>{r.assessment}</td>
                    <td>{dateLabel(rowDate(r))}</td>
                    <td>
                      <button
                        type="button"
                        className="lnk"
                        disabled={downloading === r.id}
                        onClick={() => {
                          setDownloading(r.id);
                          download.mutate({ engagementId: r.engagement_id, reportId: r.id });
                        }}
                      >
                        <i className="fas fa-download" /> {downloading === r.id ? "Preparing…" : "PDF"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </main>
  );
}
