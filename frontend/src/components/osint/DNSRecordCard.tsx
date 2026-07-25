/**
 * DNSRecordCard — DNS records display component.
 */

import Card from "../ui/Card";
import CopyButton from "../ui/CopyButton";

interface DNSRecord {
  type: string;
  values: string[];
}

export default function DNSRecordCard({ records }: { records: DNSRecord[] }) {
  if (!records.length) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
          DNS Records
        </h3>
        <p className="text-gray-500 text-sm">No DNS records found.</p>
      </Card>
    );
  }

  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        DNS Records
      </h3>
      <div className="space-y-3">
        {records.map((record) => (
          <div key={record.type} className="p-3 bg-cerberus-gray-900 rounded-lg">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-cerberus-blue font-bold">
                {record.type}
              </span>
              <CopyButton text={record.values.join("\n")} />
            </div>
            <div className="space-y-1">
              {record.values.map((value, i) => (
                <p key={i} className="text-sm text-gray-300 font-mono">
                  {value}
                </p>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}
