/**
 * ScopePage — Uses scopeStore for local state.
 */

import { useState } from "react";
import { useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import DashboardLayout from "../components/layout/DashboardLayout";
import ScopeForm from "../components/forms/ScopeForm";
import DigitalSignatureDialog from "../components/forms/DigitalSignatureDialog";
import { scopeApi } from "../api/scopeApi";
import { useScopeStore } from "../stores/scopeStore";
import { useAuthStore } from "../store/useAuthStore";

export default function ScopePage() {
  const { engagementId } = useParams();
  const qc = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const { confirmed, setScope, setConfirmed } = useScopeStore(); // removed unused `scope`
  const [showSignature, setShowSignature] = useState(false);

  const saveMutation = useMutation({
    mutationFn: (data: any) => scopeApi.updateScope(engagementId!, data),
    onSuccess: (data) => {
      setScope(data.data);
    },
  });

  const confirmMutation = useMutation({
    mutationFn: () => scopeApi.confirmScope(engagementId!),
    onSuccess: () => {
      setConfirmed(true);
      setShowSignature(true);
      qc.invalidateQueries({ queryKey: ["scope", engagementId] });
    },
  });

  // Prefix unused parameter with underscore to suppress warning
  const handleSign = (_signedName: string) => {
    // In production: call rules_service.sign_rules()
    setShowSignature(false);
  };

  return (
    <DashboardLayout>
      <div className="max-w-3xl">
        <h1 className="text-3xl font-bold text-white mb-6">Scope of Engagement</h1>
        <div className="cyber-card">
          <ScopeForm onSubmit={(d: any) => saveMutation.mutate(d)} />
          {!confirmed && (
            <button
              onClick={() => confirmMutation.mutate()}
              disabled={confirmMutation.isPending}
              className="btn-glow w-full mt-4"
            >
              {confirmMutation.isPending ? "Confirming..." : "Confirm Scope"}
            </button>
          )}
          {confirmed && !showSignature && (
            <p className="text-center text-cerberus-green text-sm mt-4">✅ Scope confirmed</p>
          )}
        </div>
      </div>

      <DigitalSignatureDialog
        isOpen={showSignature}
        onClose={() => setShowSignature(false)}
        onSign={handleSign}
        registeredName={user?.full_name || ""}
        engagementNumber={engagementId || ""}
      />
    </DashboardLayout>
  );
}
