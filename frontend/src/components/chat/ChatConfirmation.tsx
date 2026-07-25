/** ChatConfirmation — Yes / No / Clarify buttons for scope confirmation. */
export default function ChatConfirmation({ onConfirm, onDeny, onClarify }: { onConfirm: () => void; onDeny: () => void; onClarify: () => void }) {
  return (
    <div className="flex gap-2 mb-4">
      <button onClick={onConfirm} className="px-4 py-2 bg-cerberus-green/20 border border-cerberus-green/40 text-cerberus-green text-sm rounded-lg hover:bg-cerberus-green/30">✅ Yes, correct</button>
      <button onClick={onDeny} className="px-4 py-2 bg-red-500/20 border border-red-500/40 text-red-400 text-sm rounded-lg hover:bg-red-500/30">❌ No, something's wrong</button>
      <button onClick={onClarify} className="px-4 py-2 bg-cerberus-gray-700 border border-cerberus-gray-600 text-gray-300 text-sm rounded-lg hover:border-gray-500">💬 Clarify</button>
    </div>
  );
}
