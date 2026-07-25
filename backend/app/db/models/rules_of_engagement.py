"""
Rules of Engagement Model — Legal framework for the assessment.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class RulesOfEngagement(Base):
    """Legal Rules of Engagement document."""

    __tablename__ = "rules_of_engagement"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), unique=True, nullable=False
    )

    # ─── Document Content ─────────────────────────────────────
    document_html: Mapped[str] = mapped_column(Text, nullable=False)
    document_text: Mapped[str] = mapped_column(Text, nullable=False)

    # ─── Legal Clauses ────────────────────────────────────────
    authorization_clause: Mapped[str] = mapped_column(Text, nullable=False)
    methodology_clause: Mapped[str] = mapped_column(Text, nullable=False)
    prohibited_actions_clause: Mapped[str] = mapped_column(Text, nullable=False)
    client_obligations_clause: Mapped[str] = mapped_column(Text, nullable=False)
    liability_clause: Mapped[str] = mapped_column(Text, nullable=False)
    confidentiality_clause: Mapped[str] = mapped_column(Text, nullable=False)

    # ─── Status ───────────────────────────────────────────────
    is_signed: Mapped[bool] = mapped_column(Boolean, default=False)

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    signed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="rules")
