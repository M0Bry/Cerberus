"""SecurityAlert, AlertRule, Incident, IncidentResponse."""

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AlertType(str, enum.Enum):  # noqa: UP042
    ANOMALY = "anomaly"
    BRUTE_FORCE = "brute_force"
    INTRUSION = "intrusion"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"


class AlertSeverity(str, enum.Enum):  # noqa: UP042
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, enum.Enum):  # noqa: UP042
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_type: Mapped[AlertType] = mapped_column(Enum(AlertType), nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    related_user_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    evidence_refs: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.OPEN
    )
    auto_defense_actions: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )
    assigned_to: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("security_alerts.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), nullable=False
    )
    timeline: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    affected_resources: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    status: Mapped[str] = mapped_column(String(50), default="detected")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
