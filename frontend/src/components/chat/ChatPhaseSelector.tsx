/** ChatPhaseSelector — Phase selection buttons (OSINT, RedTeam, Risk). */
const phases = [{ id: "osint", label: "OSINT", icon: "🔍" }, { id: "redteam", label: "Red Team", icon: "🎯" }, { id: "risk", label: "Risk Assessment", icon: "📊" }];
export default function ChatPhaseSelector({ selected, onSelect }: { selected: string[]; onSelect: (id: string) => void }) {
  return (
    <div className="flex gap-2 mb-4">
      {phases.map((p) => (
        <button key={p.id} onClick={() => onSelect(p.id)} className={`px-4 py-2 rounded-lg text-sm border transition-all ${selected.includes(p.id) ? "border-cerberus-blue bg-cerberus-blue/10 text-cerberus-blue" : "border-cerberus-gray-600 text-gray-400 hover:border-gray-500"}`}>{p.icon} {p.label}</button>
      ))}
    </div>
  );
}
