"""Webhook replay protection + OTP purpose separation.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-19

- webhook_events: one row per processed Stripe webhook event id. A repeated
  delivery of the same id is a no-op (replay protection on top of the
  HMAC signature + 5-minute signature tolerance).
- otp_verifications.purpose: separates registration-verification codes from
  the hardened admin portal's 2FA codes so the two flows never read each
  other's rows.
"""

from alembic import op
import sqlalchemy as sa

revision: str = "0005"
down_revision: str = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_events",
        sa.Column("id", sa.String(length=255), primary_key=True),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.execute(
        "ALTER TABLE otp_verifications "
        "ADD COLUMN IF NOT EXISTS purpose VARCHAR(20) NOT NULL DEFAULT 'registration'"
    )


def downgrade() -> None:
    op.drop_table("webhook_events")
    op.execute("ALTER TABLE otp_verifications DROP COLUMN IF EXISTS purpose")
