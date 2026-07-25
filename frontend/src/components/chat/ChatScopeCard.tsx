/** ChatScopeCard — Scope summary card displayed in chat. */
export default function ChatScopeCard({ scope, onConfirm, onEdit }: { scope: any; onConfirm: () => void; onEdit: () => void }) {
  return (
    <div className="bg-cerberus-gray-800 border border-cerberus-gray-700 rounded-xl p-4 max-w-lg">
      <h4 className="text-sm font-semibold text-white mb-2">📋 Scope Summary</h4>
      <div className="text-xs text-gray-400 space-y-1 mb-4">
        <p><strong>Organization:</strong> {scope.organization || "—"}</p>
        <p><strong>Targets:</strong> {scope.targets || "—"}</p>
        <p><strong>Duration:</strong> {scope.duration || "—"}</p>
      </div>
      <div className="flex gap-2">
        <button onClick={onConfirm} className="flex-1 px-3 py-2 bg-cerberus-green/20 border border-cerberus-green/40 text-cerberus-green text-xs rounded-lg hover:bg-cerberus-green/30">✅ Confirm</button>
        <button onClick={onEdit} className="flex-1 px-3 py-2 bg-cerberus-gray-700 border border-cerberus-gray-600 text-gray-300 text-xs rounded-lg hover:border-gray-500">✏️ Edit</button>
      </div>
    </div>
  );
}
