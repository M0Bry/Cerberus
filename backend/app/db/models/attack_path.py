"""
Attack Path Models — AI-generated attack scenarios and execution tracking.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AttackPathStatus(str, enum.Enum):  # noqa: UP042
    IDENTIFIED = "identified"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    FAILED = "failed"
    SKIPPED = "skipped"


class AttackPath(Base):
    """AI-identified attack path/scenario."""

    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    # ─── Path Details ─────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    initial_entry_point: Mapped[str] = mapped_column(Text, nullable=False)
    expected_impact: Mapped[str] = mapped_column(Text, nullable=False)
    technical_feasibility: Mapped[float] = mapped_column(Float, default=0.0)
    business_impact: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    priority: Mapped[int] = mapped_column(Integer, default=0)

    # ─── Status ───────────────────────────────────────────────
    status: Mapped[AttackPathStatus] = mapped_column(
        Enum(AttackPathStatus),
        default=AttackPathStatus.IDENTIFIED,
    )

    # ─── Result ───────────────────────────────────────────────
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="attack_paths")
    steps = relationship("AttackPathStep", back_populates="attack_path", lazy="selectin")


class AttackPathStep(Base):
    """Individual step within an attack path."""

    __tablename__ = "attack_path_steps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    attack_path_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_paths.id"), index=True, nullable=False
    )

    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    tool: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool | None] = mapped_column(nullable=True)

    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    attack_path = relationship("AttackPath", back_populates="steps")
