/** ChatHeader — Chat header (session info + status). */
import StatusIndicator from "../ui/StatusIndicator";
export default function ChatHeader({ title, status, onBack }: { title: string; status?: string; onBack?: () => void }) {
  return (
    <header className="flex items-center justify-between px-6 py-3 border-b border-cerberus-gray-700 bg-cerberus-gray-900/80 backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <span className="text-xl">🛡️</span>
        <div><h1 className="font-bold text-white text-sm">{title}</h1>{status && <span className="text-[10px] text-cerberus-blue font-mono">{status}</span>}</div>
      </div>
      <div className="flex items-center gap-4">
        <StatusIndicator status="active" label="Online" />
        {onBack && <button onClick={onBack} className="text-xs text-gray-400 hover:text-white">← Back</button>}
      </div>
    </header>
  );
}
