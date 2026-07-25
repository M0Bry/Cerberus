"""
Report Model — Generated penetration testing reports.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class ReportStatus(str, enum.Enum):  # noqa: UP042
    GENERATING = "generating"
    GENERATED = "generated"
    SIGNED = "signed"
    DELIVERED = "delivered"


class Report(Base):
    """Generated penetration testing report."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    # ─── Report Details ───────────────────────────────────────
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    overall_security_score: Mapped[float] = mapped_column(Float, default=0.0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # ─── Content Sections ─────────────────────────────────────
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    methodology: Mapped[str | None] = mapped_column(Text, nullable=True)
    detailed_findings: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_roadmap: Mapped[str | None] = mapped_column(Text, nullable=True)
    overall_assessment: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Storage ──────────────────────────────────────────────
    pdf_storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Status ───────────────────────────────────────────────
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus),
        default=ReportStatus.GENERATING,
    )

    # ─── Timestamps ───────────────────────────────────────────
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    emailed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="reports")
