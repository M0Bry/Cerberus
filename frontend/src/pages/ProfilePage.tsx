/**
 * Profile Page — Uses useUserProfile hook for real data.
 */

import { useState, useEffect } from "react";
import DashboardLayout from "../components/layout/DashboardLayout";
import { useUserProfile } from "../hooks/useUserProfile";

export default function ProfilePage() {
  const [isEditing, setIsEditing] = useState(false);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const { data: profile, isLoading, updateProfile } = useUserProfile();
  const p = profile as any;

  const [form, setForm] = useState({
    full_name: "", company_name: "", job_title: "", phone_number: "", company_location: "",
  });

  useEffect(() => {
    if (p) {
      setForm({
        full_name: p.full_name || "",
        company_name: p.company_name || "",
        job_title: p.job_title || "",
        phone_number: p.phone_number || "",
        company_location: p.company_location || "",
      });
    }
  }, [p]);

  const handleSave = () => {
    updateProfile.mutate(form);
    setIsEditing(false);
  };

  const fields = [
    { label: "Full Name", key: "full_name", value: p?.full_name },
    { label: "Email", key: "email", value: p?.email },
    { label: "Company", key: "company_name", value: p?.company_name },
    { label: "Job Title", key: "job_title", value: p?.job_title },
    { label: "Phone", key: "phone_number", value: p?.phone_number },
    { label: "Location", key: "company_location", value: p?.company_location },
  ];

  return (
    <DashboardLayout activeItem="profile">
      <div className="max-w-3xl space-y-8">
        <h1 className="text-3xl font-bold text-white">Profile & Settings</h1>

        <div className="cyber-card">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Personal Information</h2>
            <button
              onClick={() => setIsEditing(!isEditing)}
              className="px-4 py-2 text-sm border border-cerberus-gray-600 rounded-lg text-gray-300 hover:border-cerberus-blue transition-colors"
            >
              {isEditing ? "Cancel" : "Edit"}
            </button>
          </div>

          {isLoading ? (
            <p className="text-gray-400">Loading profile...</p>
          ) : (
            <div className="grid grid-cols-2 gap-6">
              {fields.map((field) => (
                <div key={field.label}>
                  <label className="text-xs text-gray-400 uppercase tracking-wider">{field.label}</label>
                  {isEditing && field.key !== "email" ? (
                    <input
                      type="text"
                      className="cyber-input mt-1"
                      value={(form as any)[field.key] || ""}
                      onChange={(e) => setForm({ ...form, [field.key]: e.target.value })}
                    />
                  ) : (
                    <p className="text-white mt-1">{field.value || "—"}</p>
                  )}
                </div>
              ))}
            </div>
          )}

          {isEditing && (
            <div className="mt-6 flex gap-3">
              <button onClick={handleSave} className="btn-glow" disabled={updateProfile.isPending}>
                {updateProfile.isPending ? "Saving..." : "Save Changes"}
              </button>
              <button onClick={() => setIsEditing(false)} className="px-6 py-3 border border-cerberus-gray-600 rounded-lg text-gray-300 hover:border-gray-500 transition-colors">
                Cancel
              </button>
            </div>
          )}
        </div>

        <div className="cyber-card">
          <h2 className="text-xl font-semibold text-white mb-6">Security Settings</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-cerberus-gray-900 rounded-lg">
              <div>
                <h3 className="text-white font-medium">Password</h3>
                <p className="text-sm text-gray-400">Last changed: Unknown</p>
              </div>
              <button onClick={() => setShowPasswordForm(!showPasswordForm)} className="px-4 py-2 text-sm border border-cerberus-gray-600 rounded-lg text-gray-300 hover:border-cerberus-blue transition-colors">
                Change Password
              </button>
            </div>
            {showPasswordForm && (
              <div className="p-4 bg-cerberus-gray-900 rounded-lg space-y-4">
                <div><label className="text-sm text-gray-300">Current Password</label><input type="password" className="cyber-input mt-1" /></div>
                <div><label className="text-sm text-gray-300">New Password</label><input type="password" className="cyber-input mt-1" /></div>
                <div><label className="text-sm text-gray-300">Confirm New Password</label><input type="password" className="cyber-input mt-1" /></div>
                <button className="btn-glow">Update Password</button>
              </div>
            )}
            <div className="flex items-center justify-between p-4 bg-cerberus-gray-900 rounded-lg">
              <div><h3 className="text-white font-medium">Multi-Factor Authentication</h3><p className="text-sm text-gray-400">Add an extra layer of security</p></div>
              <span className="px-2 py-0.5 text-xs bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded-full">Not Enabled</span>
            </div>
          </div>
        </div>

        <div className="cyber-card">
          <h2 className="text-xl font-semibold text-white mb-4">Account Information</h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-400">Status:</span><span className="ml-2 text-cerberus-green">{p?.status || "—"}</span></div>
            <div><span className="text-gray-400">Role:</span><span className="ml-2 text-white">{p?.role || "—"}</span></div>
            <div><span className="text-gray-400">Member Since:</span><span className="ml-2 text-white">{p?.created_at ? new Date(p.created_at).toLocaleDateString() : "—"}</span></div>
            <div><span className="text-gray-400">Last Login:</span><span className="ml-2 text-white">{p?.last_login_at ? new Date(p.last_login_at).toLocaleDateString() : "—"}</span></div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
