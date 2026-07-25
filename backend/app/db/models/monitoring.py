"""MonitoringEvent, HealthCheck, SystemMetric, BlockedIP."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    ip_range: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    blocked_by: Mapped[str] = mapped_column(String(50), default="system")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    unblocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class SystemMetric(Base):
    __tablename__ = "system_metrics"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str] = mapped_column(String(20), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
