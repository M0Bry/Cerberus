"""
Scope of Engagement Model — Defines authorized testing targets and exclusions.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AssetType(str, enum.Enum):  # noqa: UP042
    """Types of assets in the engagement scope."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    WEB_APPLICATION = "web_application"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"
    MOBILE_APP = "mobile_app"
    NETWORK_RANGE = "network_range"
    OTHER = "other"


class ScopeOfEngagement(Base):
    """Scope of Engagement document."""

    __tablename__ = "scopes_of_engagement"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), unique=True, nullable=False
    )

    # ─── Scope Summary ────────────────────────────────────────
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    testing_objective: Mapped[str] = mapped_column(Text, nullable=False)
    testing_period_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    testing_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Constraints ──────────────────────────────────────────
    is_non_destructive: Mapped[bool] = mapped_column(Boolean, default=True)
    max_impact_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    maintenance_windows: Mapped[str | None] = mapped_column(Text, nullable=True)
    emergency_contact: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    legal_restrictions: Mapped[str | None] = mapped_column(Text, nullable=True)
    compliance_requirements: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # ─── Selected Phases ──────────────────────────────────────
    include_osint: Mapped[bool] = mapped_column(Boolean, default=True)
    include_red_team: Mapped[bool] = mapped_column(Boolean, default=True)
    include_risk_assessment: Mapped[bool] = mapped_column(Boolean, default=True)
    include_report_generation: Mapped[bool] = mapped_column(Boolean, default=True)

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="scope")
    assets = relationship(
        "ScopeAsset", back_populates="scope", lazy="selectin"
    )


class ScopeAsset(Base):
    """Individual asset within the engagement scope."""

    __tablename__ = "scope_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    scope_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scopes_of_engagement.id"),
        index=True,
        nullable=False,
    )

    # ─── Asset Details ────────────────────────────────────────
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType), nullable=False
    )
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    exclusion_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    scope = relationship("ScopeOfEngagement", back_populates="assets")
