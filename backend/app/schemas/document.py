"""
Document Schemas — Request/Response models for document upload.
"""

from datetime import datetime

from pydantic import BaseModel


class DocumentUploadResponse(BaseModel):
    success: bool = True
    document_id: str
    filename: str
    file_size_bytes: int
    validation_status: str
    message: str = "Document uploaded successfully. Validation in progress."


class DocumentItem(BaseModel):
    id: str
    original_filename: str
    file_size_bytes: int
    mime_type: str
    validation_status: str
    uploaded_at: datetime
    validated_at: datetime | None

    class Config:
        from_attributes = True


class DocumentListResponse(BaseModel):
    success: bool = True
    engagement_id: str
    documents: list[DocumentItem]


class DocumentValidationResponse(BaseModel):
    success: bool = True
    document_id: str
    validation_status: str
    malware_scan_result: str | None
    validation_notes: str | None
