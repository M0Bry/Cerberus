/**
 * Monitoring Page — Uses useMonitoring hook for real-time data.
 */

import DashboardLayout from "../components/layout/DashboardLayout";
import { useMonitoring } from "../hooks/useMonitoring";
import StatusIndicator from "../components/ui/StatusIndicator";

export default function MonitoringPage() {
  const { dashboard, alerts, blockedIPs } = useMonitoring();
  const d = dashboard.data as any;
  const a = alerts.data as any;
  const b = blockedIPs.data as any;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-white">Continuous Monitoring</h1>

        {/* Health Status */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { name: "API", status: "active", uptime: d?.uptime_percentage ?? "99.9%" },
            { name: "Database", status: "active", uptime: "99.8%" },
            { name: "Redis", status: "active", uptime: "100%" },
            { name: "AI Engine", status: "active", uptime: "99.5%" },
          ].map((s) => (
            <div key={s.name} className="cyber-card text-center">
              <StatusIndicator status={s.status as any} />
              <h3 className="text-white font-medium mt-2">{s.name}</h3>
              <p className="text-xs text-gray-400">Uptime: {s.uptime}</p>
            </div>
          ))}
        </div>

        {/* Active Alerts */}
        <div className="cyber-card">
          <h2 className="text-lg font-semibold text-white mb-4">
            Active Alerts {a?.total ? `(${a.total})` : ""}
          </h2>
          {a?.items?.length ? (
            <div className="space-y-2">
              {a.items.map((alert: any) => (
                <div key={alert.id} className="flex items-center justify-between p-3 bg-cerberus-gray-900 rounded-lg">
                  <div>
                    <p className="text-sm text-white font-medium">{alert.title}</p>
                    <p className="text-xs text-gray-400">{alert.description}</p>
                  </div>
                  <span className={`px-2 py-0.5 text-xs rounded-full ${
                    alert.severity === "critical" ? "bg-red-500/20 text-red-400" :
                    alert.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                    "bg-yellow-500/20 text-yellow-400"
                  }`}>
                    {alert.severity}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <span className="text-3xl block mb-2">✅</span>
              <p>No active alerts. All systems nominal.</p>
            </div>
          )}
        </div>

        {/* Blocked IPs */}
        <div className="cyber-card">
          <h2 className="text-lg font-semibold text-white mb-4">
            Blocked IPs {b?.total ? `(${b.total})` : ""}
          </h2>
          {b?.blocked_ips?.length ? (
            <div className="space-y-2">
              {b.blocked_ips.map((ip: any) => (
                <div key={ip.id} className="flex items-center justify-between p-3 bg-cerberus-gray-900 rounded-lg">
                  <span className="text-sm text-white font-mono">{ip.ip_address}</span>
                  <span className="text-xs text-gray-400">{ip.reason}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <p>No IPs currently blocked.</p>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
