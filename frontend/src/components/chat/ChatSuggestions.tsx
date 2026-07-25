/** ChatSuggestions — Quick suggestion chips. */
export default function ChatSuggestions({ suggestions, onSelect }: { suggestions: string[]; onSelect: (s: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {suggestions.map((s) => (
        <button key={s} onClick={() => onSelect(s)} className="px-3 py-1.5 text-xs bg-cerberus-gray-800 border border-cerberus-gray-600 rounded-full text-gray-400 hover:text-cerberus-blue hover:border-cerberus-blue transition-all">{s}</button>
      ))}
    </div>
  );
}
