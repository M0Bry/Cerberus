/**
 * OSINTProgress — OSINT phase progress tracker with module status.
 */

import Badge from "../ui/Badge";
import ProgressBar from "../ui/ProgressBar";

interface ModuleStatus {
  name: string;
  status: "pending" | "running" | "completed" | "failed";
  icon: string;
}

interface OSINTProgressProps {
  progress: number;
  modules: ModuleStatus[];
}

export default function OSINTProgress({ progress, modules }: OSINTProgressProps) {
  return (
    <div className="space-y-4">
      <ProgressBar value={progress} label="Overall Progress" color="blue" />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {modules.map((mod) => (
          <div
            key={mod.name}
            className={`p-3 rounded-lg border transition-all ${
              mod.status === "completed"
                ? "border-cerberus-green/40 bg-cerberus-green/5"
                : mod.status === "running"
                ? "border-cerberus-blue/40 bg-cerberus-blue/5 animate-pulse"
                : mod.status === "failed"
                ? "border-red-500/40 bg-red-500/5"
                : "border-cerberus-gray-700 bg-cerberus-gray-800/50"
            }`}
          >
            <div className="flex items-center gap-2">
              <span>{mod.icon}</span>
              <span className="text-xs text-gray-300 font-medium">{mod.name}</span>
            </div>
            <Badge
              variant={
                mod.status === "completed"
                  ? "success"
                  : mod.status === "running"
                  ? "info"
                  : mod.status === "failed"
                  ? "danger"
                  : "default"
              }
              size="sm"
            >
              {mod.status}
            </Badge>
          </div>
        ))}
      </div>
    </div>
  );
}
