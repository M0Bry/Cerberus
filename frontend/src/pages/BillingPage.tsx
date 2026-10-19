/**
 * Billing Page — plans, subscription state, Stripe-hosted checkout.
 *
 * Wiring:
 *   GET  /payments/plans        → purchasable plan cards (Starter/Professional)
 *   GET  /payments/subscription → status panel (404 = none)
 *   POST /payments/checkout     → redirect to Stripe's hosted payment page
 *   ?checkout=success           → poll until the webhook flips us to active
 *   ?checkout=cancelled         → "no charge was made" banner
 *
 * Enterprise is sales-driven (custom pricing) — card links to contact,
 * exactly like the landing pricing section.
 */
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useAccess } from "../hooks/useAccess";
import { useSearchParams } from "react-router-dom";
import UserChip from "../components/layout/UserChip";
import { paymentsApi, type Plan, type Subscription } from "../api/paymentsApi";
import { formatDateTime } from "../utils/formatters";

const FEATURES: Record<string, string[]> = {
  Starter: [
    "1 assessment per month",
    "1 active scope · up to 3 domains",
    "Reports kept 30 days",
    "1 seat · email support, 48h reply",
  ],
  Professional: [
    "4 assessments per month",
    "3 concurrent scopes · 10 domains each",
    "Reports kept 12 months",
    "5 seats · priority support, 24h reply",
  ],
  Enterprise: [
    "12+ assessments per month, custom volume",
    "Unlimited scopes & domains",
    "Custom retention · SSO · audit export",
    "Unlimited seats · dedicated manager, 24/7 SLA",
  ],
};

const PLAN_COMMON =
  "AI scoping conversation · automated OSINT · attack-path planning · controlled testing · business risk score · evidence PDF report";

const priceLabel = (p: Plan) => {
  const dollars = (p.price_cents / 100).toLocaleString("en-US", { maximumFractionDigits: 0 });
  return `$${dollars}`;
};
const perLabel = (p: Plan) =>
  p.interval === "year" ? "/yr" : p.interval === "quarter" ? "/3mo" : "/mo";

const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  active: { label: "Active", color: "#4ade80", bg: "rgba(74,222,128,.12)" },
  trialing: { label: "Trialing", color: "#60a5fa", bg: "rgba(96,165,250,.12)" },
  past_due: { label: "Payment due", color: "#fbbf24", bg: "rgba(251,191,36,.12)" },
  unpaid: { label: "Unpaid", color: "#fbbf24", bg: "rgba(251,191,36,.12)" },
  paused: { label: "Paused", color: "#fbbf24", bg: "rgba(251,191,36,.12)" },
  canceled: { label: "Canceled", color: "#9ca3af", bg: "rgba(156,163,175,.12)" },
  incomplete: { label: "Incomplete", color: "#9ca3af", bg: "rgba(156,163,175,.12)" },
};

export default function BillingPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [checkoutError, setCheckoutError] = useState<string | null>(null);
  const [paymentsDown, setPaymentsDown] = useState(false);
  const waited = useRef(0);

  const checkoutResult = searchParams.get("checkout");
  const isActivating = checkoutResult === "success";

  const plansQuery = useQuery({
    queryKey: ["payments", "plans"],
    queryFn: async () => (await paymentsApi.listPlans()).data,
  });

  const subQuery = useQuery({
    queryKey: ["payments", "subscription"],
    queryFn: async () => (await paymentsApi.getSubscription()).data,
    refetchInterval: isActivating ? 2_000 : false,
  });
  const sub: Subscription | undefined = subQuery.data;
  const hasActive = !!sub && ["active", "trialing", "past_due", "paused"].includes(sub.status);

  /* trial / suspension state — shown when there is no paid subscription */
  const { data: access, refreshAccess } = useAccess();
  const isTrial = access?.state === "trial";
  const isSuspended = access?.state === "suspended";

  /* once the webhook flips us to a live state, clear the ?checkout param */
  useEffect(() => {
    if (!isActivating || !sub) return;
    if (["active", "trialing", "past_due", "paused"].includes(sub.status)) {
      const next = new URLSearchParams(searchParams);
      next.delete("checkout");
      setSearchParams(next, { replace: true });
      // Subscription just went live — refresh the access state (lifts any
      // trial-expiry suspension server-side).
      refreshAccess();
    }
    waited.current += 1;
  }, [sub, isActivating, searchParams, setSearchParams, refreshAccess]);

  /* stop the "activating" banner after 60s — the sync is automatic either way */
  useEffect(() => {
    if (!isActivating) return;
    waited.current = 0;
    const t = window.setInterval(() => (waited.current += 1), 2_000);
    return () => window.clearInterval(t);
  }, [isActivating]);

  const subscribe = useMutation({
    mutationFn: async (planId: string) => (await paymentsApi.createCheckout(planId)).data,
    onSuccess: (res) => {
      setCheckoutError(null);
      window.location.href = res.checkout_url; // Stripe's hosted page — no card data here
    },
    onError: (err: any) => {
      const status = err?.response?.status;
      if (status === 503) setPaymentsDown(true);
      setCheckoutError(err?.response?.data?.detail || "Something went wrong starting checkout. Try again.");
    },
  });

  const dismissResult = () => {
    const next = new URLSearchParams(searchParams);
    next.delete("checkout");
    setSearchParams(next, { replace: true });
    setCheckoutError(null);
  };

  const plans: Plan[] = plansQuery.data ?? [];
  const meta = sub ? STATUS_META[sub.status] ?? STATUS_META.incomplete : undefined;

  const cardButton = (p: Plan, popular: boolean) => {
    if (paymentsDown || plansQuery.isLoading) {
      return (
        <button className={`btn btn-${popular ? "primary" : "outline"}`} style={{ width: "100%", marginTop: 22 }} disabled>
          {plansQuery.isLoading ? "Loading…" : "Unavailable"}
        </button>
      );
    }
    const isCurrent = sub?.plan?.id === p.id && hasActive;
    if (isCurrent) {
      return (
        <button className={`btn btn-${popular ? "primary" : "outline"}`} style={{ width: "100%", marginTop: 22 }} disabled>
          Current plan
        </button>
      );
    }
    if (hasActive) {
      return (
        <button className={`btn btn-${popular ? "primary" : "outline"}`} style={{ width: "100%", marginTop: 22 }} disabled title="Cancel your current subscription before switching">
          Switch plan
        </button>
      );
    }
    return (
      <button
        className={`btn btn-${popular ? "primary" : "outline"}`}
        style={{ width: "100%", marginTop: 22 }}
        disabled={subscribe.isPending}
        onClick={() => subscribe.mutate(p.id)}
      >
        {subscribe.isPending ? "Redirecting…" : popular ? "Start Now" : "Get Started"}
      </button>
    );
  };

  return (
    <main className="main">
      <div className="topbar">
        <div className="crumb">
          <small>Your account</small>
          <h1>Billing</h1>
        </div>
        <UserChip />
      </div>

      {/* ── checkout result banners ─────────────────────────── */}
      {isActivating && (
        <div
          style={{
            margin: "0 0 18px",
            padding: "14px 18px",
            borderRadius: 10,
            border: "1px solid rgba(74,222,128,.35)",
            background: "rgba(74,222,128,.08)",
            display: "flex",
            alignItems: "center",
            gap: 12,
          }}
        >
          <i className="fas fa-circle-notch fa-spin" style={{ color: "#4ade80" }} />
          <div style={{ flex: 1 }}>
            <strong>Payment received — activating your subscription…</strong>
            <div style={{ fontSize: 13, opacity: 0.75 }}>
              {waited.current >= 30
                ? "Still waiting on the payment confirmation. It activates automatically — check back in a moment."
                : "This usually takes a few seconds. You can leave this page; it completes on its own."}
            </div>
          </div>
        </div>
      )}
      {checkoutResult === "cancelled" && (
        <div
          style={{
            margin: "0 0 18px",
            padding: "14px 18px",
            borderRadius: 10,
            border: "1px solid var(--border-strong)",
            background: "rgba(255,255,255,.03)",
            display: "flex",
            alignItems: "center",
            gap: 12,
          }}
        >
          <i className="fas fa-circle-xmark" style={{ color: "var(--text-muted)" }} />
          <div style={{ flex: 1 }}>
            <strong>Checkout canceled — no charge was made.</strong>
            <div style={{ fontSize: 13, opacity: 0.75 }}>Pick a plan below whenever you're ready.</div>
          </div>
          <button className="btn btn-ghost" onClick={dismissResult}>
            Dismiss
          </button>
        </div>
      )}
      {paymentsDown && (
        <div
          style={{
            margin: "0 0 18px",
            padding: "14px 18px",
            borderRadius: 10,
            border: "1px solid rgba(251,191,36,.35)",
            background: "rgba(251,191,36,.08)",
          }}
        >
          <i className="fas fa-triangle-exclamation" style={{ color: "#fbbf24" }} />{" "}
          <strong>Payments are being finalized.</strong>{" "}
          <span style={{ fontSize: 13, opacity: 0.75 }}>
            Check back shortly, or write to us through the Contact section on the home page.
          </span>
        </div>
      )}
      {checkoutError && (
        <div
          style={{
            margin: "0 0 18px",
            padding: "12px 16px",
            borderRadius: 10,
            border: "1px solid rgba(207,39,49,.4)",
            background: "rgba(207,39,49,.08)",
            color: "var(--text-primary)",
            fontSize: 14,
          }}
        >
          <i className="fas fa-triangle-exclamation" style={{ color: "var(--accent)" }} /> {checkoutError}
        </div>
      )}

      {/* ── current subscription ────────────────────────────── */}
      <div className="panel" style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          {sub && meta ? (
            <>
              <span
                style={{
                  padding: "5px 14px",
                  borderRadius: 999,
                  border: `1px solid ${meta.color}`,
                  color: meta.color,
                  background: meta.bg,
                  fontFamily: "var(--font-display)",
                  fontSize: 12,
                  letterSpacing: 1.5,
                  textTransform: "uppercase",
                }}
              >
                {meta.label}
              </span>
              <div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: 17, letterSpacing: 1 }}>
                  {sub.plan.name} · {priceLabel(sub.plan)}
                  {perLabel(sub.plan)}
                </div>
                <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
                  {sub.current_period_end
                    ? `Renews ${formatDateTime(sub.current_period_end)}`
                    : "Billing period synced by the payment gateway"}
                  {sub.cancel_at_period_end && hasActive ? " · cancels at period end" : ""}
                </div>
              </div>
              {sub.status === "past_due" && (
                <span style={{ fontSize: 13, color: "#fbbf24" }}>
                  <i className="fas fa-triangle-exclamation" /> Payment failed — update your card to keep access.
                </span>
              )}
            </>
          ) : isSuspended ? (
            <>
              <span
                style={{
                  padding: "5px 14px",
                  borderRadius: 999,
                  border: "1px solid #f87171",
                  color: "#f87171",
                  background: "rgba(248,113,113,.12)",
                  fontFamily: "var(--font-display)",
                  fontSize: 12,
                  letterSpacing: 1.5,
                  textTransform: "uppercase",
                }}
              >
                Suspended
              </span>
              <div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: 17, letterSpacing: 1, color: "#fca5a5" }}>
                  <i className="fas fa-lock" /> Your account is suspended
                </div>
                <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
                  Your 7-day free trial has ended and no payment has been received. New
                  assessments are locked until a subscription is active — choosing a plan
                  below restores access immediately.
                </div>
              </div>
            </>
          ) : isTrial ? (
            <>
              <span
                style={{
                  padding: "5px 14px",
                  borderRadius: 999,
                  border: "1px solid #60a5fa",
                  color: "#60a5fa",
                  background: "rgba(96,165,250,.12)",
                  fontFamily: "var(--font-display)",
                  fontSize: 12,
                  letterSpacing: 1.5,
                  textTransform: "uppercase",
                }}
              >
                Free Trial
              </span>
              <div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: 17, letterSpacing: 1 }}>
                  Full access — <b style={{ color: "#60a5fa" }}>{access?.trial_days_left} day{access?.trial_days_left === 1 ? "" : "s"} left</b>
                </div>
                <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
                  Your trial ends {formatDateTime(access?.trial_ends_at)} — after that a plan
                  is required or the account is suspended. Pick one below to keep everything
                  going smoothly. Secure checkout is handled by Stripe.
                </div>
              </div>
            </>
          ) : (
            <>
              <span
                style={{
                  padding: "5px 14px",
                  borderRadius: 999,
                  border: "1px solid var(--border-strong)",
                  color: "var(--text-secondary)",
                  fontFamily: "var(--font-display)",
                  fontSize: 12,
                  letterSpacing: 1.5,
                  textTransform: "uppercase",
                }}
              >
                No subscription
              </span>
              <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
                You're not on a plan yet. Pick one below — secure checkout is handled by Stripe.
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── plans ───────────────────────────────────────────── */}
      <div className="pricing-grid" style={{ maxWidth: 1080, margin: "0 auto" }}>
        {plans.map((p) => {
          const popular = p.name === "Professional";
          return (
            <div key={p.id} className={`pricing-card fade-up${popular ? " popular" : ""}`}>
              <div className="plan-name">{p.name}</div>
              <div className="plan-price">
                {priceLabel(p)}
                <span>{perLabel(p)}</span>
              </div>
              <div className="plan-desc">{p.description}</div>
              <ul className="plan-limits">
                {(FEATURES[p.name] ?? []).map((f) => (
                  <li key={f}>
                    <i className="fas fa-check" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <div className="plan-common">
                <span className="common-title">Full workflow on every plan</span>
                {PLAN_COMMON}
              </div>
              {cardButton(p, popular)}
            </div>
          );
        })}

        {/* Enterprise — sales-driven, like the landing page */}
        <div className="pricing-card fade-up">
          <div className="plan-name">Enterprise</div>
          <div className="plan-price">Custom</div>
          <div className="plan-desc">For organizations with complex environments.</div>
          <ul className="plan-limits">
            {(FEATURES.Enterprise ?? []).map((f) => (
              <li key={f}>
                <i className="fas fa-check" />
                <span>{f}</span>
              </li>
            ))}
          </ul>
          <div className="plan-common">
            <span className="common-title">Full workflow on every plan</span>
            {PLAN_COMMON}
          </div>
          <a href="/#contact" className="btn btn-outline" style={{ width: "100%", marginTop: 22 }}>
            Contact Sales
          </a>
        </div>
      </div>

      <p className="pricing-note" style={{ textAlign: "center", marginTop: 18 }}>
        No plan changes how Cerberus works — only how often you unleash it. Billing is processed securely by
        Stripe; card details never touch Cerberus servers.
      </p>
    </main>
  );
}
