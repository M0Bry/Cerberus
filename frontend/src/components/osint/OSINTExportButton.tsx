/**
 * OSINTExportButton — Export OSINT results (JSON/CSV).
 */

import { useState } from "react";
import { osintApi } from "../../api/osintApi";
import Button from "../ui/Button";

export default function OSINTExportButton({ engagementId }: { engagementId: string }) {
  const [loading, setLoading] = useState(false);

  const handleExport = async (format: "json" | "csv") => {
    setLoading(true);
    try {
      const response = await osintApi.exportResults(engagementId, format);
      const blob = new Blob([JSON.stringify(response.data, null, 2)], {
        type: format === "json" ? "application/json" : "text/csv",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `osint_results_${engagementId}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex gap-2">
      <Button
        variant="secondary"
        size="sm"
        onClick={() => handleExport("json")}
        loading={loading}
      >
        📥 Export JSON
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={() => handleExport("csv")}
        loading={loading}
      >
        📥 Export CSV
      </Button>
    </div>
  );
}
