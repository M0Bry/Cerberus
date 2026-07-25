"""
Document Upload Endpoints — Upload and validate supporting documents.
"""

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.document import (
    DocumentListResponse,
    DocumentUploadResponse,
    DocumentValidationResponse,
)
from app.services.document_service import DocumentService

router = APIRouter()


@router.post("/{engagement_id}/upload", response_model=DocumentUploadResponse)
async def upload_document(
    engagement_id: str,
    file: UploadFile = File(...),                    # noqa: B008
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Upload a supporting document for an engagement.

    The file undergoes validation pipeline:
    1. Format verification
    2. Malware scanning
    3. Metadata extraction
    4. Relevance validation
    5. Encryption and storage
    """
    doc_service = DocumentService(db)
    return await doc_service.upload_document(engagement_id, current_user.id, file)


@router.get("/{engagement_id}", response_model=DocumentListResponse)
async def list_documents(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """List all uploaded documents for an engagement."""
    doc_service = DocumentService(db)
    return await doc_service.list_documents(engagement_id, current_user.id)


@router.get("/{document_id}/status", response_model=DocumentValidationResponse)
async def get_validation_status(
    document_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the validation status of an uploaded document."""
    doc_service = DocumentService(db)
    return await doc_service.get_validation_status(document_id, current_user.id)
