/**
 * AssetInventoryTable — Discovered assets inventory table.
 */

import DataTable from "../ui/DataTable";
import Badge from "../ui/Badge";

interface Asset {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  risk_score: number;
}

export default function AssetInventoryTable({ assets }: { assets: Asset[] }) {
  const columns = [
    { key: "type", label: "Type", sortable: true },
    { key: "value", label: "Value" },
    { key: "source", label: "Source" },
    {
      key: "confidence",
      label: "Confidence",
      render: (item: Asset) => (
        <Badge variant={item.confidence > 0.7 ? "success" : item.confidence > 0.4 ? "warning" : "default"}>
          {(item.confidence * 100).toFixed(0)}%
        </Badge>
      ),
    },
    {
      key: "risk_score",
      label: "Risk",
      render: (item: Asset) => (
        <Badge variant={item.risk_score > 0.7 ? "danger" : item.risk_score > 0.4 ? "warning" : "success"}>
          {item.risk_score.toFixed(1)}
        </Badge>
      ),
    },
  ];

  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
        Asset Inventory ({assets.length})
      </h3>
      <DataTable
        columns={columns}
        data={assets}
        pageSize={20}
        emptyMessage="No assets discovered yet."
      />
    </div>
  );
}
