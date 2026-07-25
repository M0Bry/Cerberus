"""
Audit Log Model — Comprehensive activity logging for security and compliance.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AuditAction(str, enum.Enum):  # noqa: UP042
    """Types of auditable actions."""
    USER_REGISTERED = "user_registered"
    USER_VERIFIED = "user_verified"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_LOGIN_FAILED = "user_login_failed"
    PASSWORD_CHANGED = "password_changed"
    ENGAGEMENT_CREATED = "engagement_created"
    SCOPE_DEFINED = "scope_defined"
    RULES_GENERATED = "rules_generated"
    DOCUMENT_SIGNED = "document_signed"
    DOCUMENT_UPLOADED = "document_uploaded"
    ASSESSMENT_STARTED = "assessment_started"
    PHASE_COMPLETED = "phase_completed"
    ASSESSMENT_COMPLETED = "assessment_completed"
    REPORT_GENERATED = "report_generated"
    SECURITY_ALERT = "security_alert"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BLOCKED_REQUEST = "blocked_request"
    ADMIN_ACTION = "admin_action"


class AuditSeverity(str, enum.Enum):  # noqa: UP042
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditLog(Base):
    """Audit log entry."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), index=True, nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=True
    )

    # ─── Log Details ──────────────────────────────────────────
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False)
    severity: Mapped[AuditSeverity] = mapped_column(
        Enum(AuditSeverity), default=AuditSeverity.INFO
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ─── Request Context ──────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    request_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Timestamp ────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
        index=True,
    )

    # ─── Relationships ────────────────────────────────────────
    user = relationship("User", back_populates="audit_logs")
    engagement = relationship("Engagement", back_populates="audit_logs")
