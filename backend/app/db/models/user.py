"""
User Model — Stores registered user accounts and organization details.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class UserStatus(str, enum.Enum):  # noqa: UP042
    """User account verification status."""
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class UserRole(str, enum.Enum):  # noqa: UP042
    """User role within the platform."""
    USER = "user"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class User(Base):
    """User account model."""

    __tablename__ = "users"

    # ─── Primary Key ──────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, index=True
    )

    # ─── Personal Information ─────────────────────────────────
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    phone_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    profile_image_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Organization Details ─────────────────────────────────
    company_name: Mapped[str] = mapped_column(String(255), nullable=False)
    job_title: Mapped[str] = mapped_column(String(255), nullable=False)
    company_location: Mapped[str | None] = mapped_column(String(500), nullable=True)
    company_logo_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Authentication ───────────────────────────────────────
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus),
        default=UserStatus.PENDING_VERIFICATION,
        nullable=False,
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole),
        default=UserRole.USER,
        nullable=False,
    )
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Security / Registration Metadata ─────────────────────
    registration_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    registration_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    registration_browser: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_device: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_location: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # ─── Timestamps ───────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),    # noqa: UP017
        onupdate=lambda: datetime.now(timezone.utc),   # noqa: UP017
        nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagements = relationship("Engagement", back_populates="user", lazy="selectin")
    sessions = relationship("UserSession", back_populates="user", lazy="selectin")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="selectin")
    notifications = relationship("Notification", back_populates="user", lazy="selectin")
