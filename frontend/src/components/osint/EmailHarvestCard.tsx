/**
 * EmailHarvestCard — Email harvesting results display.
 */

import Card from "../ui/Card";
import Badge from "../ui/Badge";
import CopyButton from "../ui/CopyButton";

interface EmailResult {
  email: string;
  source: string;
  confidence: number;
}

export default function EmailHarvestCard({ emails }: { emails: EmailResult[] }) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Email Harvesting ({emails.length})
      </h3>

      {emails.length === 0 ? (
        <p className="text-gray-500 text-sm">No email addresses discovered.</p>
      ) : (
        <div className="space-y-2">
          {emails.map((email, i) => (
            <div
              key={i}
              className="flex items-center justify-between p-2 bg-cerberus-gray-900 rounded-lg"
            >
              <div>
                <p className="text-sm text-white font-mono">{email.email}</p>
                <p className="text-xs text-gray-500">Source: {email.source}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={email.confidence > 0.7 ? "success" : "warning"}>
                  {(email.confidence * 100).toFixed(0)}%
                </Badge>
                <CopyButton text={email.email} />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
