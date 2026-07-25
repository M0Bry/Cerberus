/**
 * DomainEnumCard — Domain enumeration results.
 */

import Card from "../ui/Card";
import Badge from "../ui/Badge";

interface DomainInfo {
  domain: string;
  ip_addresses: string[];
  technologies: string[];
  headers: Record<string, string>;
  status_code: number;
}

export default function DomainEnumCard({ data }: { data: DomainInfo }) {
  return (
    <Card>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Domain Enumeration
      </h3>

      <div className="space-y-4">
        <div>
          <p className="text-xs text-gray-400 mb-1">Domain</p>
          <p className="text-white font-mono">{data.domain}</p>
        </div>

        {data.ip_addresses.length > 0 && (
          <div>
            <p className="text-xs text-gray-400 mb-1">IP Addresses</p>
            <div className="flex flex-wrap gap-2">
              {data.ip_addresses.map((ip) => (
                <Badge key={ip} variant="info">{ip}</Badge>
              ))}
            </div>
          </div>
        )}

        {data.technologies.length > 0 && (
          <div>
            <p className="text-xs text-gray-400 mb-1">Technologies</p>
            <div className="flex flex-wrap gap-2">
              {data.technologies.map((tech) => (
                <Badge key={tech} variant="default">{tech}</Badge>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
