/** ReportViewPage — Single report viewer. */
import { useParams } from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import ReportViewer from "../components/reports/ReportViewer";

export default function ReportViewPage() {
  const { reportId } = useParams();
  return (
    <DashboardLayout>
      <h1 className="text-3xl font-bold text-white mb-6">Report Viewer</h1>
      {/* ✅ No error – prop type now accepts string | undefined */}
      <ReportViewer reportId={reportId} />
    </DashboardLayout>
  );
}
