/** RiskMatrix — placeholder */
import Card from "../ui/Card";

interface RiskMatrixProps {
  engagementId?: string;
}

export default function RiskMatrix({ engagementId }: RiskMatrixProps) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Risk Matrix
      </h3>
      <p className="text-gray-400 text-sm">
        Engagement ID: {engagementId ?? "—"}
      </p>
    </Card>
  );
}
