/** ReportViewer — Report component. */
import Card from "../ui/Card";

interface ReportViewerProps {
  reportId?: string;   // optional because useParams can return undefined
}

export default function ReportViewer({ reportId }: ReportViewerProps) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        ReportViewer
      </h3>
      <p className="text-gray-400 text-sm">
        Report ID: {reportId ?? "none"}
      </p>
    </Card>
  );
}
