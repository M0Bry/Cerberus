/** RiskScoreCard — placeholder */
import Card from "../ui/Card";

interface RiskScoreCardProps {
  engagementId?: string;
}

export default function RiskScoreCard({ engagementId }: RiskScoreCardProps) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Risk Score Card
      </h3>
      <p className="text-gray-400 text-sm">
        Engagement ID: {engagementId ?? "—"}
      </p>
    </Card>
  );
}
