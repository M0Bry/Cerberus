/** ChatSidebar — Sidebar with past conversations list. */
export default function ChatSidebar({ sessions, activeId, onSelect }: { sessions: any[]; activeId?: string; onSelect: (id: string) => void }) {
  return (
    <div className="p-4 space-y-2">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Conversations</h3>
      {sessions.map((s) => (
        <button key={s.id} onClick={() => onSelect(s.id)} className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${activeId === s.id ? "bg-cerberus-blue/10 text-cerberus-blue" : "text-gray-400 hover:bg-cerberus-gray-800"}`}>{s.title || "Untitled"}</button>
      ))}
    </div>
  );
}
