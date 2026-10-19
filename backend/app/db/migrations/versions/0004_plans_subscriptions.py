"""Plans + Subscriptions tables (Stripe-backed subscription payments).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-19

NOTE on enum casing: the ORM models use ``sqlalchemy.Enum(PythonClass)``,
which stores the UPPER-CASE member *names* (this matches the rest of the
schema, e.g. users.role = 'ADMIN'/'USER'). The Postgres enum values below
therefore use those names so the column type is identical to the one the
ORM creates/reads.
"""

from alembic import op
import sqlalchemy as sa

revision: str = "0004"
down_revision: str = "0003"
branch_labels = None
depends_on = None

# PlanInterval names.
_PLAN_INTERVAL = ("MONTH", "QUARTER", "YEAR")
# SubscriptionStatus names.
_SUB_STATUS = (
    "INCOMPLETE",
    "TRIALING",
    "ACTIVE",
    "PAST_DUE",
    "CANCELED",
    "UNPAID",
    "PAUSED",
)


def upgrade() -> None:
    op.create_table(
        "plans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("price_cents", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="usd"),
        sa.Column(
            "interval",
            sa.Enum(*_PLAN_INTERVAL, name="planinterval"),
            nullable=False,
        ),
        sa.Column(
            "stripe_price_id", sa.String(length=120), nullable=True, unique=True
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "plan_id",
            sa.String(length=36),
            sa.ForeignKey("plans.id"),
            nullable=False,
        ),
        sa.Column("stripe_customer_id", sa.String(length=120), nullable=False),
        sa.Column(
            "stripe_subscription_id", sa.String(length=120), nullable=False, unique=True
        ),
        sa.Column(
            "status",
            sa.Enum(*_SUB_STATUS, name="subscriptionstatus"),
            nullable=False,
            server_default="INCOMPLETE",
        ),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancel_at_period_end", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_subscriptions_user_id", "subscriptions", ["user_id"])
    op.create_index(
        "ix_subscriptions_user_status", "subscriptions", ["user_id", "status"]
    )

    # Plan lineup (matches the landing page pricing section). Enterprise is
    # sales-driven (custom pricing) so it is not in the purchasable list —
    # is_active=False keeps it out of GET /payments/plans while remaining
    # available for reference. Prices are in cents and can be re-priced at
    # any time without a migration.
    plan = sa.table(
        "plans",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("price_cents", sa.Integer),
        sa.column("currency", sa.String),
        sa.column("interval", sa.Enum(*_PLAN_INTERVAL, name="planinterval")),
        sa.column("is_active", sa.Boolean),
    )
    op.bulk_insert(
        plan,
        [
            {
                "id": "plan-starter",
                "name": "Starter",
                "description": "A first, honest look at your exposure.",
                "price_cents": 5900,
                "currency": "usd",
                "interval": "MONTH",
                "is_active": True,
            },
            {
                "id": "plan-professional",
                "name": "Professional",
                "description": "For teams that assess on a rhythm, not once.",
                "price_cents": 18900,
                "currency": "usd",
                "interval": "MONTH",
                "is_active": True,
            },
            {
                "id": "plan-enterprise",
                "name": "Enterprise",
                "description": "For organizations with complex environments.",
                "price_cents": 0,
                "currency": "usd",
                "interval": "MONTH",
                "is_active": False,
            },
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_subscriptions_user_status", table_name="subscriptions")
    op.drop_index("ix_subscriptions_user_id", table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_table("plans")
