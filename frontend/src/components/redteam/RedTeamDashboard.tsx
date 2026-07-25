/** RedTeamDashboard — Red Team component. */
import Card from "../ui/Card";

interface RedTeamDashboardProps {
  engagementId?: string; // optional because useParams can return undefined
}

export default function RedTeamDashboard({ engagementId }: RedTeamDashboardProps) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        RedTeamDashboard
      </h3>
      <p className="text-gray-400 text-sm">
        Engagement: {engagementId ?? "none"}
      </p>
    </Card>
  );
}
