"""Plan Model — subscribable service plans (pricing + Stripe linkage)."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class PlanInterval(str, enum.Enum):  # noqa: UP042
    """Billing interval for a plan."""

    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


class Plan(Base):
    """A purchasable subscription plan.

    Prices are stored in the smallest currency unit (cents). The actual
    charge is created in Stripe; ``stripe_price_id`` links a plan row to
    its Stripe Price object (created in the Stripe dashboard — merchant
    setup stays entirely outside this codebase).
    """

    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Price in cents (e.g. 4900 = $49.00).
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="usd", nullable=False)

    interval: Mapped[PlanInterval] = mapped_column(
        Enum(PlanInterval), nullable=False
    )

    # Link to the Stripe Price object (price_...). Nullable until the
    # merchant creates the product/price in Stripe; checkout refuses
    # plans that are not linked yet.
    stripe_price_id: Mapped[str | None] = mapped_column(
        String(120), unique=True, nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
        nullable=False,
    )
