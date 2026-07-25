/**
 * SubdomainTable — Subdomain enumeration results table.
 */

import DataTable from "../ui/DataTable";

interface Subdomain {
  subdomain: string;
  ip?: string;
  status?: number;
  technology?: string;
  source: string;
}

export default function SubdomainTable({ subdomains }: { subdomains: Subdomain[] }) {
  const columns = [
    { key: "subdomain", label: "Subdomain", sortable: true },
    { key: "ip", label: "IP Address" },
    { key: "status", label: "Status", render: (item: Subdomain) => item.status || "—" },
    { key: "technology", label: "Technology", render: (item: Subdomain) => item.technology || "—" },
    { key: "source", label: "Source" },
  ];

  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Subdomain Enumeration ({subdomains.length})
      </h3>
      <DataTable
        columns={columns}
        data={subdomains}
        pageSize={20}
        emptyMessage="No subdomains discovered yet."
      />
    </div>
  );
}
