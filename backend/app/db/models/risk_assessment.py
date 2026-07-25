"""
Risk Assessment Model — Business impact analysis for confirmed vulnerabilities.
"""

import enum  # noqa: I001
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class RiskLevel(str, enum.Enum):  # noqa: UP042
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(Base):
    """Risk assessment for a confirmed vulnerability."""

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )
    vulnerability_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id"), nullable=False
    )

    # ─── Risk Scoring ─────────────────────────────────────────
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), nullable=False)
    likelihood_of_exploitation: Mapped[float] = mapped_column(Float, default=0.0)
    complexity_required: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    privileges_obtainable: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    asset_sensitivity: Mapped[float] = mapped_column(Float, default=0.0)
    cumulative_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    # ─── Business Consequences ────────────────────────────────
    potential_consequences: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )
    affected_services: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    regulatory_implications: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # ─── Remediation Priority ─────────────────────────────────
    remediation_priority: Mapped[int] = mapped_column(Integer, default=0)
    estimated_remediation_effort: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    # ─── Timestamps ───────────────────────────────────────────
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="risk_assessments")
    vulnerability = relationship("Vulnerability")
