"""Payment Service — Stripe checkout + webhook synchronization.

Security model (per project requirements):
- Card data NEVER touches this server. Checkout runs on Stripe's hosted
  page; we only create the session (amount + price id) and receive
  signed webhook events.
- Merchant keys live backend-only (.env). The frontend never sees them.
- Every webhook event is HMAC-verified with STRIPE_WEBHOOK_SECRET before
  a single byte is trusted.
- Webhook handling is idempotent: events upsert by stripe id, so
  duplicates/stale ordering cannot corrupt state.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

import stripe
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.notification import Notification, NotificationType
from app.db.models.plan import Plan
from app.db.models.subscription import Subscription, SubscriptionStatus
from app.db.models.user import User

logger = structlog.get_logger()

_ACTIVE_STATUSES = {
    SubscriptionStatus.ACTIVE,
    SubscriptionStatus.TRIALING,
    SubscriptionStatus.PAST_DUE,
    SubscriptionStatus.PAUSED,
}

# Stripe subscription states we know how to store.
_KNOWN_STATUSES = {s.value for s in SubscriptionStatus}


class PaymentService:
    """Stripe-backed subscription lifecycle."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._configure_stripe()

    # ─── Stripe plumbing ─────────────────────────────────────

    @staticmethod
    def _configure_stripe() -> None:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        # Overridable base URL lets development verify the full flow
        # against a local mock without any code change.
        stripe.api_base = settings.STRIPE_BASE_URL

    @staticmethod
    def is_configured() -> bool:
        return bool(settings.STRIPE_SECRET_KEY)

    # ─── Plans ───────────────────────────────────────────────

    async def list_active_plans(self) -> list[Plan]:
        result = await self.db.execute(
            select(Plan).where(Plan.is_active.is_(True)).order_by(Plan.price_cents)
        )
        return list(result.scalars().all())

    async def get_plan(self, plan_id: str) -> Plan | None:
        result = await self.db.execute(select(Plan).where(Plan.id == plan_id))
        return result.scalar_one_or_none()

    # ─── Subscriptions (user side) ───────────────────────────

    async def get_user_subscription(self, user_id: str) -> Subscription | None:
        """The user's most recent subscription (any status)."""
        result = await self.db.execute(
            select(Subscription)
            .where(Subscription.user_id == user_id)
            .order_by(Subscription.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _find_by_stripe_sub(self, stripe_subscription_id: str) -> Subscription | None:
        result = await self.db.execute(
            select(Subscription).where(
                Subscription.stripe_subscription_id == stripe_subscription_id
            )
        )
        return result.scalar_one_or_none()

    # ─── Checkout ────────────────────────────────────────────

    async def create_checkout_session(
        self, user: User, plan: Plan
    ) -> tuple[str, str]:
        """Create a Stripe Checkout session (hosted page).

        Returns (session_id, checkout_url).
        Raises PaymentError with an HTTP-friendly detail on any refusal.
        """
        if not plan.is_active:
            raise PaymentError(404, "This plan is no longer available.")
        if not plan.stripe_price_id:
            raise PaymentError(
                503,
                "This plan is not connected to the payment gateway yet. "
                "Please try another plan or contact support.",
            )

        existing = await self.get_user_subscription(user.id)
        if existing and existing.status in _ACTIVE_STATUSES:
            raise PaymentError(
                409,
                "You already have an active subscription. "
                "Cancel it before starting a new one.",
            )

        # Reuse the user's Stripe customer when one exists.
        customer_id: str | None = (
            existing.stripe_customer_id if existing else None
        )
        if not customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                name=user.full_name,
                metadata={"user_id": user.id},
            )
            customer_id = str(customer.id)

        success_url = (
            f"{settings.FRONTEND_BASE_URL}/billing"
            f"?checkout=success&session_id={{CHECKOUT_SESSION_ID}}"
        )
        cancel_url = f"{settings.FRONTEND_BASE_URL}/billing?checkout=cancelled"

        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": plan.stripe_price_id, "quantity": 1}],
            client_reference_id=user.id,
            metadata={"plan_id": plan.id, "user_id": user.id},
            success_url=success_url,
            cancel_url=cancel_url,
        )
        logger.info(
            "checkout_session_created",
            user_id=user.id,
            plan_id=plan.id,
            session_id=session.id,
            mode=settings.STRIPE_MODE,
        )
        return str(session.id), str(session.url)

    # ─── Webhooks (Stripe → us) ──────────────────────────────

    async def handle_webhook_event(self, event: dict[str, Any]) -> None:
        """Idempotently apply a verified Stripe event to our database."""
        etype = event.get("type", "")
        obj = event.get("data", {}).get("object", {})

        if etype == "checkout.session.completed":
            await self._on_checkout_completed(obj)
        elif etype in (
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        ):
            await self._on_subscription_changed(obj)
        elif etype == "invoice.payment_failed":
            await self._on_payment_failed(obj)
        elif etype == "invoice.payment_succeeded":
            await self._on_payment_succeeded(obj)
        else:
            logger.debug("webhook_event_ignored", event_type=etype)

    async def _on_checkout_completed(self, session: dict[str, Any]) -> None:
        """Payment captured: the subscription becomes active.

        The subscription object itself arrives separately (via
        customer.subscription.*), so we create the row here and the
        subscription events refine its state.
        """
        if session.get("mode") != "subscription":
            return
        stripe_sub_id = session.get("subscription")
        if not stripe_sub_id:
            return

        meta = session.get("metadata") or {}
        user_id = session.get("client_reference_id") or meta.get("user_id")
        plan_id = meta.get("plan_id")
        if not user_id or not plan_id:
            logger.error(
                "checkout_completed_missing_identity",
                session_id=session.get("id"),
            )
            return

        # Defensive: the identity must reference a user we actually know.
        # (A signed event with a foreign/typo'd client_reference_id must be
        # logged and ignored, not crash with an FK violation.)
        user_check = await self.db.execute(select(User.id).where(User.id == str(user_id)))
        if user_check.scalar_one_or_none() is None:
            logger.error(
                "checkout_completed_unknown_user",
                session_id=session.get("id"),
                user_id=str(user_id),
            )
            return

        existing = await self._find_by_stripe_sub(str(stripe_sub_id))
        if existing is None:
            sub = Subscription(
                id=str(uuid.uuid4()),
                user_id=str(user_id),
                plan_id=str(plan_id),
                stripe_customer_id=str(session.get("customer") or ""),
                stripe_subscription_id=str(stripe_sub_id),
                status=SubscriptionStatus.ACTIVE,
            )
            self.db.add(sub)
            await self.db.flush()
            logger.info(
                "subscription_activated",
                user_id=str(user_id),
                plan_id=str(plan_id),
                stripe_subscription_id=str(stripe_sub_id),
            )
        # Payment just went live — lift any trial-expiry suspension.
        await self._restore_user_access(str(user_id))

    async def _on_subscription_changed(self, sub_obj: dict[str, Any]) -> None:
        stripe_sub_id = sub_obj.get("id")
        if not stripe_sub_id:
            return
        sub = await self._find_by_stripe_sub(str(stripe_sub_id))
        if sub is None:
            # We only create rows from checkout.session.completed; an
            # unknown subscription here means identity was missing then.
            logger.error(
                "subscription_event_unknown_sub",
                stripe_subscription_id=str(stripe_sub_id),
            )
            return
        status_raw = str(sub_obj.get("status", ""))
        if status_raw in _KNOWN_STATUSES:
            sub.status = SubscriptionStatus(status_raw)
        sub.cancel_at_period_end = bool(
            sub_obj.get("cancel_at_period_end", sub.cancel_at_period_end)
        )
        period_end = sub_obj.get("current_period_end")
        if isinstance(period_end, (int, float)):
            sub.current_period_end = datetime.fromtimestamp(
                int(period_end), tz=timezone.utc
            )
        await self.db.flush()
        logger.info(
            "subscription_synced",
            stripe_subscription_id=str(stripe_sub_id),
            status=status_raw,
        )
        # Subscription returned to a paid state — lift any suspension.
        if sub.status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING):
            await self._restore_user_access(sub.user_id)

    async def _on_payment_failed(self, invoice: dict[str, Any]) -> None:
        stripe_sub_id = invoice.get("subscription")
        if not stripe_sub_id:
            return
        sub = await self._find_by_stripe_sub(str(stripe_sub_id))
        if sub is None:
            return
        sub.status = SubscriptionStatus.PAST_DUE
        await self.db.flush()

        notif = Notification(
            id=str(uuid.uuid4()),
            user_id=sub.user_id,
            engagement_id=None,
            notification_type=NotificationType.WARNING,
            title="Subscription payment failed",
            message=(
                "The latest payment for your Cerberus subscription could "
                "not be processed. Please update your payment method in "
                "your billing settings."
            ),
            action_url="/billing",
        )
        self.db.add(notif)
        await self.db.flush()
        logger.warning(
            "subscription_payment_failed",
            user_id=sub.user_id,
            stripe_subscription_id=str(stripe_sub_id),
        )

    async def _on_payment_succeeded(self, invoice: dict[str, Any]) -> None:
        stripe_sub_id = invoice.get("subscription")
        if not stripe_sub_id:
            return
        sub = await self._find_by_stripe_sub(str(stripe_sub_id))
        if sub is None:
            return
        if sub.status in (SubscriptionStatus.PAST_DUE, SubscriptionStatus.UNPAID):
            sub.status = SubscriptionStatus.ACTIVE
            await self.db.flush()
        period_end = invoice.get("period_end")
        if isinstance(period_end, (int, float)):
            sub.current_period_end = datetime.fromtimestamp(
                int(period_end), tz=timezone.utc
            )
            await self.db.flush()
        # The failed payment was recovered — lift any suspension.
        if sub.status == SubscriptionStatus.ACTIVE:
            await self._restore_user_access(sub.user_id)

    async def _restore_user_access(self, user_id: str) -> None:
        """Un-suspend the account once a subscription is active.

        The product rule: a suspended (trial-expired) account stays
        suspended until payment — payment arriving lifts it automatically.
        """
        from app.services.access_service import AccessService

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user is None:
            return
        await AccessService(self.db).restore_access(user)


class PaymentError(Exception):
    """Refusal with an HTTP status for the endpoint layer."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
