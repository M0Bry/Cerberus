"""
Uploaded Document Model — Tracks client-uploaded supporting documents.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class DocumentValidationStatus(str, enum.Enum):  # noqa: UP042
    PENDING = "pending"
    VALIDATING = "validating"
    PASSED = "passed"
    FAILED_MALWARE = "failed_malware"
    FAILED_FORMAT = "failed_format"
    FAILED_SIZE = "failed_size"


class UploadedDocument(Base):
    """Client-uploaded supporting document."""

    __tablename__ = "uploaded_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), index=True, nullable=False
    )

    # ─── File Information ─────────────────────────────────────
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # ─── Validation ───────────────────────────────────────────
    validation_status: Mapped[DocumentValidationStatus] = mapped_column(
        Enum(DocumentValidationStatus),
        default=DocumentValidationStatus.PENDING,
    )
    malware_scan_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_extracted: Mapped[str | None] = mapped_column(Text, nullable=True)
    validation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Timestamps ───────────────────────────────────────────
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),  # noqa: UP017
    )
    validated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ─── Relationships ────────────────────────────────────────
    engagement = relationship("Engagement", back_populates="documents")
