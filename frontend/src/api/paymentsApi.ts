/**
 * Payments API — subscription plans, checkout, subscription state, access.
 *
 *   GET  /payments/plans        (public)  → Plan[]
 *   POST /payments/checkout     (auth)    → {checkout_url, session_id}
 *   GET  /payments/subscription (auth)    → Subscription | 404
 *   GET  /access                (auth)    → AccessInfo (trial/paid/suspended)
 *
 * Card data never touches our servers: checkout redirects to Stripe's
 * hosted page and state syncs back via signed webhooks.
 */
import axiosAuth from "./axiosAuth";
import axiosInstance from "./axiosInstance";

export interface Plan {
  id: string;
  name: string;
  description: string | null;
  price_cents: number;
  currency: string;
  interval: string;
}

export interface Subscription {
  id: string;
  status:
    | "incomplete"
    | "trialing"
    | "active"
    | "past_due"
    | "canceled"
    | "unpaid"
    | "paused";
  cancel_at_period_end: boolean;
  current_period_end: string | null;
  created_at: string;
  plan: Plan;
}

export interface CheckoutResponse {
  success: boolean;
  message: string;
  checkout_url: string;
  session_id: string;
}

export interface AccessInfo {
  /** "paid" | "trial" | "suspended" */
  state: string;
  plan_name: string | null;
  subscription_status: string | null;
  trial_ends_at: string;
  trial_days_left: number;
  is_admin: boolean;
}

export const paymentsApi = {
  listPlans: () => axiosAuth.get<Plan[]>("/payments/plans"),
  createCheckout: (planId: string) =>
    axiosInstance.post<CheckoutResponse>("/payments/checkout", { plan_id: planId }),
  getSubscription: () => axiosInstance.get<Subscription>("/payments/subscription"),
  getAccess: () => axiosInstance.get<AccessInfo>("/access"),
};
