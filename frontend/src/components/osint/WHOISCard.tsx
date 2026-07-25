/**
 * WHOISCard — WHOIS lookup results display.
 */

import Card from "../ui/Card";

interface WHOISData {
  registrar?: string;
  creation_date?: string;
  expiry_date?: string;
  name_servers?: string[];
  registrant?: {
    name?: string;
    organization?: string;
    country?: string;
  };
}

export default function WHOISCard({ data }: { data: WHOISData }) {
  if (!data || !data.registrar) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
          WHOIS Information
        </h3>
        <p className="text-gray-500 text-sm">No WHOIS data available.</p>
      </Card>
    );
  }

  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        WHOIS Information
      </h3>
      <div className="space-y-2 text-sm">
        {data.registrar && (
          <div className="flex justify-between">
            <span className="text-gray-400">Registrar</span>
            <span className="text-white">{data.registrar}</span>
          </div>
        )}
        {data.creation_date && (
          <div className="flex justify-between">
            <span className="text-gray-400">Created</span>
            <span className="text-white">{data.creation_date}</span>
          </div>
        )}
        {data.expiry_date && (
          <div className="flex justify-between">
            <span className="text-gray-400">Expires</span>
            <span className="text-white">{data.expiry_date}</span>
          </div>
        )}
        {data.name_servers && data.name_servers.length > 0 && (
          <div>
            <span className="text-gray-400">Name Servers</span>
            <div className="mt-1 space-y-1">
              {data.name_servers.map((ns, i) => (
                <p key={i} className="text-white font-mono text-xs">{ns}</p>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
