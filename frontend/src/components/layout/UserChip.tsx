/**
 * UserChip — topbar identity chip (new design).
 * The new front-end hard-codes "John Doe / Acme Corp · Verified"; this one
 * renders the signed-in user from the auth store.
 */
import { useAuthStore } from "../../store/useAuthStore";

function initials(name?: string | null): string {
  return (name || "")
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() || "")
    .join("") || "U";
}

export default function UserChip() {
  const user = useAuthStore((s) => s.user);
  const verified = user?.status === "verified";

  return (
    <div className="user-chip">
      <div className="avatar">{initials(user?.full_name)}</div>
      <div>
        <div className="nm">{user?.full_name || "—"}</div>
        <div className="rl">
          {[user?.company_name, verified ? "Verified" : "Pending"].filter(Boolean).join(" · ") || "—"}
        </div>
      </div>
    </div>
  );
}
