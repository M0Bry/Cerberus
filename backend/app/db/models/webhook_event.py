"""Webhook Event Model — replay protection for signed payment webhooks.

Stripe may redeliver an event (and an attacker who captures the signed
payload could replay it within the signature-tolerance window). We record
every processed event id; a second delivery of the same id is a no-op.

The marker row is inserted in the SAME transaction as the state change:
if processing fails the marker rolls back too, so a legitimate Stripe
retry can still be processed.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class WebhookEvent(Base):
    """One processed Stripe webhook event (id is the Stripe event id)."""

    __tablename__ = "webhook_events"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
        nullable=False,
    )
