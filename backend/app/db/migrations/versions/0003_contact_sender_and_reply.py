"""Add sender account link + admin reply to contact_messages.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-19
"""

from alembic import op
import sqlalchemy as sa

revision: str = "0003"
down_revision: str = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "contact_messages",
        sa.Column("user_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_contact_messages_user_id", "contact_messages", ["user_id"]
    )
    op.add_column(
        "contact_messages", sa.Column("reply", sa.Text(), nullable=True)
    )
    op.add_column(
        "contact_messages",
        sa.Column("replied_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("contact_messages", "replied_at")
    op.drop_column("contact_messages", "reply")
    op.drop_index("ix_contact_messages_user_id", table_name="contact_messages")
    op.drop_column("contact_messages", "user_id")
