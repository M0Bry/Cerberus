"""
Digital Signature Model — Cryptographic authorization for Rules of Engagement.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class DigitalSignature(Base):
    """Digital signature for Rules of Engagement authorization."""

    __tablename__ = "digital_signatures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), unique=True, nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )

    # ─── Signature Data ───────────────────────────────────────
    signed_name: Mapped[str] = mapped_column(String(500), nullable=False)
    cryptographic_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── PDF Reference ────────────────────────────────────────
    pdf_storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Timestamps ───────────────────────────────────────────
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="signature")
