/**
 * Timeline — Timeline component matching the reference design.
 */
const MONO = "'Share Tech Mono', 'Courier New', monospace";

interface TimelineEvent {
  time: string;
  title: string;
  description?: string;
  severity?: string;
}

export default function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {events.map((e, i) => (
        <div key={i} style={{ display: "flex", gap: 14 }}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: e.severity === "critical" ? "#f4536b" : e.severity === "high" ? "#ff8a3d" : "#2f7dfa",
                flexShrink: 0,
              }}
            />
            {i < events.length - 1 && (
              <div style={{ width: 1, flex: 1, background: "#152238", minHeight: 24 }} />
            )}
          </div>
          <div style={{ paddingBottom: 20 }}>
            <p style={{ fontSize: 10.5, color: "#5b6a86", fontFamily: MONO }}>{e.time}</p>
            <p style={{ fontSize: 13, color: "#e8edf7", fontWeight: 700, fontFamily: MONO, marginTop: 2 }}>{e.title}</p>
            {e.description && <p style={{ fontSize: 11.5, color: "#8493ac", fontFamily: MONO, marginTop: 4 }}>{e.description}</p>}
          </div>
        </div>
      ))}
    </div>
  );
}
