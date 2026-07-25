"""
Notification Model — User-facing notifications and alerts.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class NotificationType(str, enum.Enum):  # noqa: UP042
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ALERT = "alert"
    SECURITY = "security"


class Notification(Base):
    """User notification."""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), index=True, nullable=False
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=True
    )

    # ─── Content ──────────────────────────────────────────────
    notification_type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType), default=NotificationType.INFO
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    action_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Status ───────────────────────────────────────────────
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    is_emailed: Mapped[bool] = mapped_column(Boolean, default=False)

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    user = relationship("User", back_populates="notifications")
