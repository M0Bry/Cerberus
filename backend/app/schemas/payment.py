"""Payment schemas — plans, subscriptions, checkout."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None = None
    price_cents: int
    currency: str
    interval: str


class SubscriptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    cancel_at_period_end: bool
    current_period_end: datetime | None = None
    created_at: datetime
    plan: PlanOut


class AdminPlanOut(PlanOut):
    """Admin view of a plan — includes the Stripe link fields.

    ``stripe_price_id`` is operator-only data: it must never appear in
    the public /payments/plans payload (see PlanOut above).
    """

    is_active: bool
    stripe_price_id: str | None = None


class PlanUpdateRequest(BaseModel):
    """Partial plan update (admin-only). All fields optional."""

    name: str | None = None
    description: str | None = None
    price_cents: int | None = None
    currency: str | None = None
    interval: str | None = None
    is_active: bool | None = None
    stripe_price_id: str | None = None


class CreateCheckoutRequest(BaseModel):
    plan_id: str


class CheckoutResponse(BaseModel):
    success: bool = True
    message: str
    checkout_url: str
    session_id: str
