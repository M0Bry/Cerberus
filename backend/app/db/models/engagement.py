"""
Engagement Model — Core penetration testing engagement record.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class EngagementStatus(str, enum.Enum):  # noqa: UP042
    """Engagement lifecycle status."""
    DRAFT = "draft"
    SCOPE_DEFINED = "scope_defined"
    RULES_GENERATED = "rules_generated"
    AUTHORIZED = "authorized"
    INITIALIZING = "initializing"
    OSINT_IN_PROGRESS = "osint_in_progress"
    OSINT_COMPLETE = "osint_complete"
    ATTACK_PLANNING = "attack_planning"
    ATTACK_PLANNING_COMPLETE = "attack_planning_complete"
    RED_TEAM_IN_PROGRESS = "red_team_in_progress"
    RED_TEAM_COMPLETE = "red_team_complete"
    RISK_ASSESSMENT = "risk_assessment"
    RISK_ASSESSMENT_COMPLETE = "risk_assessment_complete"
    REPORT_GENERATING = "report_generating"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Engagement(Base):
    """Penetration testing engagement."""

    __tablename__ = "engagements"

    # ─── Primary Key ──────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, index=True
    )
    engagement_number: Mapped[str] = mapped_column(
        String(20), unique=True, index=True, nullable=False
    )

    # ─── Client Reference ─────────────────────────────────────
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), index=True, nullable=False
    )

    # ─── Engagement Details ───────────────────────────────────
    project_name: Mapped[str] = mapped_column(String(500), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(500), nullable=False)
    objective: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Status & Progress ────────────────────────────────────
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus),
        default=EngagementStatus.DRAFT,
        nullable=False,
    )
    progress_percentage: Mapped[int] = mapped_column(Integer, default=0)
    current_phase: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    risk_level: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )
    overall_security_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )

    # ─── AI Conversation Context ──────────────────────────────
    conversation_history: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    ai_context_model: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # ─── Timeline ─────────────────────────────────────────────
    estimated_duration_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),    # noqa: UP017
        onupdate=lambda: datetime.now(timezone.utc),   # noqa: UP017
    )

    # ─── Relationships ────────────────────────────────────────
    user = relationship("User", back_populates="engagements")
    scope = relationship(
        "ScopeOfEngagement",
        back_populates="engagement",
        uselist=False,
        lazy="selectin",
    )
    rules = relationship(
        "RulesOfEngagement",
        back_populates="engagement",
        uselist=False,
        lazy="selectin",
    )
    signature = relationship(
        "DigitalSignature",
        back_populates="engagement",
        uselist=False,
        lazy="selectin",
    )
    documents = relationship(
        "UploadedDocument",
        back_populates="engagement",
        lazy="selectin",
    )
    osint_findings = relationship(
        "OSINTFinding",
        back_populates="engagement",
        lazy="selectin",
    )
    attack_paths = relationship(
        "AttackPath",
        back_populates="engagement",
        lazy="selectin",
    )
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="engagement",
        lazy="selectin",
    )
    risk_assessments = relationship(
        "RiskAssessment",
        back_populates="engagement",
        lazy="selectin",
    )
    reports = relationship(
        "Report",
        back_populates="engagement",
        lazy="selectin",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="engagement",
        lazy="selectin",
    )
