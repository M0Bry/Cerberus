/**
 * Settings Page — Profile, notifications, security settings.
 */

import DashboardLayout from "../components/layout/DashboardLayout";

export default function SettingsPage() {
  return (
    <DashboardLayout>
      <div className="max-w-3xl space-y-8">
        <h1 className="text-3xl font-bold text-white">Settings</h1>

        {/* Profile */}
        <div className="cyber-card">
          <h2 className="text-xl font-semibold text-white mb-4">Profile</h2>
          <div className="grid grid-cols-2 gap-4">
            {[{l:"Full Name",v:"—"},{l:"Email",v:"—"},{l:"Company",v:"—"},{l:"Job Title",v:"—"}].map(f => (
              <div key={f.l}><label className="text-xs text-gray-400 uppercase">{f.l}</label><p className="text-white mt-1">{f.v}</p></div>
            ))}
          </div>
        </div>

        {/* Notifications */}
        <div className="cyber-card">
          <h2 className="text-xl font-semibold text-white mb-4">Notification Preferences</h2>
          {["Email notifications","Push notifications","Security alerts","Report ready"].map(p => (
            <label key={p} className="flex items-center justify-between py-2">
              <span className="text-sm text-gray-300">{p}</span>
              <div className="w-10 h-5 bg-cerberus-gray-700 rounded-full relative cursor-pointer">
                <div className="w-4 h-4 bg-cerberus-blue rounded-full absolute top-0.5 left-0.5 transition-all" />
              </div>
            </label>
          ))}
        </div>

        {/* Security */}
        <div className="cyber-card">
          <h2 className="text-xl font-semibold text-white mb-4">Security</h2>
          <div className="space-y-3">
            <div className="flex justify-between items-center p-3 bg-cerberus-gray-900 rounded-lg">
              <div><h3 className="text-white text-sm font-medium">Password</h3><p className="text-xs text-gray-500">Last changed: Unknown</p></div>
              <button className="text-xs text-cerberus-blue hover:underline">Change</button>
            </div>
            <div className="flex justify-between items-center p-3 bg-cerberus-gray-900 rounded-lg">
              <div><h3 className="text-white text-sm font-medium">MFA</h3><p className="text-xs text-gray-500">Two-factor authentication</p></div>
              <span className="text-xs text-yellow-400">Not enabled</span>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
