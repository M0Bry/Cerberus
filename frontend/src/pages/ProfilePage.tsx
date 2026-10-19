/**
 * Profile Page — ported from the new front-end's profile.html + js/profile.js,
 * rewired from localStorage to GET /users/me (the signed-in user).
 *
 * The subscription plan is not part of the backend user schema yet, so the
 * plan card falls back to "cerberus_plan" in localStorage, and otherwise to
 * the "no paid plan" state exactly like the mock.
 */
import { Link } from "react-router-dom";
import StateLink from "../components/common/StateLink";
import { useQuery } from "@tanstack/react-query";
import { userApi } from "../api/userApi";
import { useAuthStore } from "../store/useAuthStore";
import type { User } from "../types";

const PLANS: Record<string, { price: string; desc: string; items: string[] }> = {
  Starter: {
    price: "$59/mo",
    desc: "A first, honest look at your exposure.",
    items: ["1 assessment per month", "1 active scope · up to 3 domains", "Reports kept 30 days", "1 seat · email support, 48h reply"],
  },
  Professional: {
    price: "$189/mo",
    desc: "For teams that assess on a rhythm, not once.",
    items: ["4 assessments per month", "3 concurrent scopes · 10 domains each", "Reports kept 12 months", "5 seats · priority support, 24h reply"],
  },
  Enterprise: {
    price: "Custom",
    desc: "For organizations with complex environments.",
    items: ["12+ assessments per month, custom volume", "Unlimited scopes & domains", "Custom retention · SSO · audit export", "Unlimited seats · dedicated manager, 24/7 SLA"],
  },
};

const val = (v?: string | null) => (v && v.trim() ? v : "Not provided");

export default function ProfilePage() {
  const storeUser = useAuthStore((s) => s.user);
  const { data: fresh } = useQuery({
    queryKey: ["me"],
    queryFn: async () => (await userApi.getProfile()).data as User,
    staleTime: 5 * 60_000,
  });

  const user: User | null = fresh || storeUser;

  let planKey = "";
  let photo = (user as any)?.profile_image_url || "";
  try {
    planKey = localStorage.getItem("cerberus_plan") || "";
    if (!photo) photo = localStorage.getItem("cerberus_photo") || "";
  } catch {
    /* storage unavailable */
  }
  const plan = PLANS[planKey] || null;

  return (
    <main className="main set-main">
      <div className="topbar">
        <div className="crumb">
          <small>Account</small>
          <h1>Profile</h1>
        </div>
      </div>

      <div className="set-body">
        <section className="set-card" aria-labelledby="profHead">
          <div className="set-card-top">
            <div className="prof-head">
              <div className="prof-av" id="profAv">
                {photo ? <img src={photo} alt="" style={{ width: "100%", height: "100%", objectFit: "cover", borderRadius: "50%" }} /> : (user?.full_name?.[0]?.toUpperCase() || "J")}
              </div>
              <div>
                <div className="prof-name">{val(user?.full_name)}</div>
                <div className="prof-role">{[user?.job_title, user?.company_name].filter(Boolean).join(" · ") || "Not provided"}</div>
              </div>
            </div>
            <Link className="set-btn" to="/settings#personal">
              <i className="fas fa-pen" /> Edit in Settings
            </Link>
          </div>

          <h2 className="set-h" id="profHead">
            <i className="fas fa-id-card" />
            Personal information
          </h2>
          <p className="set-p">These are the details from your registration. To change them, use Settings.</p>

          <div className="prof-grid">
            <div className="prof-field">
              <span>Full name</span>
              <b>{val(user?.full_name)}</b>
            </div>
            <div className="prof-field">
              <span>Job title</span>
              <b>{val(user?.job_title)}</b>
            </div>
            <div className="prof-field">
              <span>Organization</span>
              <b>{val(user?.company_name)}</b>
            </div>
            <div className="prof-field">
              <span>Phone number</span>
              <b>{val(user?.phone_number)}</b>
            </div>
            <div className="prof-field">
              <span>Email (registered)</span>
              <b>{val(user?.email)}</b>
            </div>
          </div>
        </section>

        <section className="set-card" aria-labelledby="planHead">
          <h2 className="set-h" id="planHead">
            <i className="fas fa-layer-group" />
            Subscription plan
          </h2>
          <p className="set-p">The plan this account is subscribed to. Every plan runs the same full workflow; plans differ in volume and retention.</p>

          <div className="plan-top">
            <div>
              <div className="prof-name">{planKey || "Free"}</div>
              <div className="plan-sub">{plan ? plan.desc : "No paid plan is active on this account."}</div>
            </div>
            <div className="plan-price-now">{plan ? plan.price : ""}</div>
          </div>

          {plan ? (
            <ul className="plan-list">
              {plan.items.map((t) => (
                <li key={t}>
                  <i className="fas fa-check" />
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="plan-note" style={{ display: "block" }}>
              Paid plans start at Starter, $59/mo. <StateLink to="/" state={{ scrollTo: "pricing" }}>Compare plans</StateLink>.
            </p>
          )}
        </section>
      </div>
    </main>
  );
}
