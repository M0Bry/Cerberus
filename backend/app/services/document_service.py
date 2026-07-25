"""
Document Service — Handles file upload, validation, and storage.
"""

import hashlib
import uuid
from pathlib import Path

import structlog
from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import FileUploadError, NotFoundError
from app.db.models.engagement import Engagement
from app.db.models.uploaded_document import (
    DocumentValidationStatus,
    UploadedDocument,
)
from app.schemas.document import (
    DocumentItem,
    DocumentListResponse,
    DocumentUploadResponse,
    DocumentValidationResponse,
)

logger = structlog.get_logger()


class DocumentService:
    """Handles document upload, validation, and management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upload_document(
        self, engagement_id: str, user_id: str, file: UploadFile
    ) -> DocumentUploadResponse:
        """Upload and validate a supporting document."""

        # Verify engagement ownership
        await self._verify_ownership(engagement_id, user_id)

        # Validate file extension
        if file.filename:
            ext = Path(file.filename).suffix.lower()
            if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
                raise FileUploadError(
                    f"File type '{ext}' is not allowed. "
                    f"Supported: {', '.join(settings.ALLOWED_UPLOAD_EXTENSIONS)}"
                )

        # Read file content
        content = await file.read()

        # Check file size
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise FileUploadError(
                f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB"
            )

        # Compute hash
        file_hash = hashlib.sha256(content).hexdigest()

        # Store file
        doc_id = str(uuid.uuid4())
        storage_dir = Path(settings.UPLOAD_DIR) / engagement_id
        storage_dir.mkdir(parents=True, exist_ok=True)
        storage_path = storage_dir / f"{doc_id}_{file.filename}"

        with open(storage_path, "wb") as f:
            f.write(content)

        # Create document record
        document = UploadedDocument(
            id=doc_id,
            engagement_id=engagement_id,
            original_filename=file.filename or "unnamed",
            storage_path=str(storage_path),
            file_size_bytes=len(content),
            mime_type=file.content_type or "application/octet-stream",
            file_hash_sha256=file_hash,
            validation_status=DocumentValidationStatus.PENDING,
        )
        self.db.add(document)
        await self.db.flush()

        # Trigger background validation (malware scan, metadata extraction)
        # from app.tasks.document_validation import validate_document
        # validate_document.delay(doc_id)

        logger.info("document_uploaded", document_id=doc_id, filename=file.filename)

        return DocumentUploadResponse(
            document_id=doc_id,
            filename=file.filename or "unnamed",
            file_size_bytes=len(content),
            validation_status="pending",
        )

    async def list_documents(
        self, engagement_id: str, user_id: str
    ) -> DocumentListResponse:
        """List all documents for an engagement."""
        await self._verify_ownership(engagement_id, user_id)

        result = await self.db.execute(
            select(UploadedDocument)
            .where(UploadedDocument.engagement_id == engagement_id)
            .order_by(UploadedDocument.uploaded_at.desc())
        )
        documents = result.scalars().all()

        return DocumentListResponse(
            engagement_id=engagement_id,
            documents=[DocumentItem.model_validate(d) for d in documents],
        )

    async def get_validation_status(
        self, document_id: str, user_id: str
    ) -> DocumentValidationResponse:
        """Get document validation status."""
        result = await self.db.execute(
            select(UploadedDocument).where(UploadedDocument.id == document_id)
        )
        document = result.scalar_one_or_none()
        if not document:
            raise NotFoundError("Document not found")

        return DocumentValidationResponse(
            document_id=document_id,
            validation_status=document.validation_status.value,
            malware_scan_result=document.malware_scan_result,
            validation_notes=document.validation_notes,
        )

    async def _verify_ownership(self, engagement_id: str, user_id: str):
        """Verify the engagement belongs to the user."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        if not result.scalar_one_or_none():
            raise NotFoundError("Engagement not found")
