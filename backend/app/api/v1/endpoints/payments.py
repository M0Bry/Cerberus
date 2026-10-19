"""Payments Endpoints — plans, checkout, subscription state, Stripe webhook.

Card data never touches this server: checkout is hosted by Stripe and
all state changes arrive as HMAC-verified webhook events.
"""

from datetime import datetime, timezone

import stripe as stripe_lib
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.models.user import User, UserStatus
from app.db.models.webhook_event import WebhookEvent
from app.db.session import get_db
from app.schemas.payment import (
    CheckoutResponse,
    CreateCheckoutRequest,
    PlanOut,
    SubscriptionOut,
)
from app.services.payment_service import PaymentError, PaymentService

router = APIRouter()
logger = structlog.get_logger()


@router.get("/plans", response_model=list[PlanOut])
async def list_plans(
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """Active subscription plans (public — pricing display)."""
    service = PaymentService(db)
    return await service.list_active_plans()


@router.post("/checkout", response_model=CheckoutResponse, status_code=200)
async def create_checkout(
    payload: CreateCheckoutRequest,
    request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Create a Stripe Checkout session for a plan.

    The buyer is redirected to Stripe's hosted payment page. This
    endpoint only returns the URL — no payment data passes through us.
    """
    if not PaymentService.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Payments are not configured on this server yet.",
        )
    if current_user.status != UserStatus.VERIFIED:
        raise HTTPException(
            status_code=403,
            detail="Verify your email address before subscribing.",
        )

    service = PaymentService(db)
    plan = await service.get_plan(payload.plan_id)
    if plan is None or not plan.is_active:
        raise HTTPException(status_code=404, detail="Plan not found.")

    try:
        session_id, url = await service.create_checkout_session(
            current_user, plan
        )
    except PaymentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    except stripe_lib.error.APIConnectionError as exc:
        logger.error("stripe_connection_error", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Payment gateway unreachable. Try again shortly.",
        )
    except stripe_lib.error.StripeError as exc:
        logger.error("stripe_api_error", error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Payment gateway error. Try again shortly.",
        )

    await db.commit()
    return CheckoutResponse(
        success=True,
        message="Checkout session created. You are being redirected to the secure payment page.",
        checkout_url=url,
        session_id=session_id,
    )


@router.get("/subscription", response_model=SubscriptionOut)
async def get_subscription(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """The current user's most recent subscription (404 if none)."""
    service = PaymentService(db)
    sub = await service.get_user_subscription(current_user.id)
    if sub is None:
        raise HTTPException(status_code=404, detail="No subscription found.")
    plan = await service.get_plan(sub.plan_id)
    if plan is None:  # plan removed from catalog — synthesize a minimal one
        plan = PlanOut(
            id=sub.plan_id,
            name="Plan (removed)",
            description=None,
            price_cents=0,
            currency="usd",
            interval="month",
        )
    return SubscriptionOut(
        id=sub.id,
        status=sub.status.value,
        cancel_at_period_end=sub.cancel_at_period_end,
        current_period_end=sub.current_period_end,
        created_at=sub.created_at,
        plan=plan,
    )


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    """Stripe webhook receiver.

    The raw body is HMAC-verified with STRIPE_WEBHOOK_SECRET before any
    part of it is trusted. Everything else is idempotent.
    """
    if not settings.STRIPE_WEBHOOK_SECRET:
        logger.warning("webhook_received_without_secret")
        raise HTTPException(
            status_code=503,
            detail="Webhook secret not configured on this server.",
        )

    payload = await request.body()
    signature = request.headers.get("Stripe-Signature", "")
    try:
        # tolerance=300: signed payloads are only trusted for 5 minutes —
        # anything older (e.g. a captured replay) is rejected.
        event = stripe_lib.Webhook.construct_event(
            payload, signature, settings.STRIPE_WEBHOOK_SECRET, tolerance=300
        )
    except ValueError as exc:  # malformed payload
        logger.warning("webhook_invalid_payload", error=str(exc))
        raise HTTPException(status_code=400, detail="Invalid payload.")
    except stripe_lib.error.SignatureVerificationError as exc:
        logger.warning("webhook_signature_mismatch", error=str(exc))
        raise HTTPException(status_code=400, detail="Invalid signature.")

    event_dict = event.to_dict()  # v16 returns a StripeObject
    event_id = str(event_dict.get("id") or "")
    if not event_id:
        logger.warning("webhook_event_missing_id")
        raise HTTPException(status_code=400, detail="Invalid payload.")

    # Replay protection: the same Stripe event id is processed at most once.
    # The marker is committed in the SAME transaction as the state change —
    # if processing fails, the marker rolls back too, so a legitimate
    # Stripe retry can still be applied.
    existing = await db.execute(
        select(WebhookEvent.id).where(WebhookEvent.id == event_id)
    )
    if existing.scalar_one_or_none():
        logger.info("webhook_event_duplicate", event_id=event_id)
        return {"received": True, "duplicate": True}
    db.add(
        WebhookEvent(
            id=event_id,
            event_type=str(event_dict.get("type", "")),
            received_at=datetime.now(timezone.utc),  # noqa: UP017
        )
    )
    try:
        await db.flush()
    except IntegrityError:
        # A concurrent delivery won the unique constraint — treat as duplicate.
        await db.rollback()
        logger.info("webhook_event_duplicate_concurrent", event_id=event_id)
        return {"received": True, "duplicate": True}

    service = PaymentService(db)
    await service.handle_webhook_event(event_dict)
    # get_db commits on success / rolls back on exception.
    return {"received": True}
