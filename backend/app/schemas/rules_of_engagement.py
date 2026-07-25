"""
Rules of Engagement Schemas — Request/Response models for RoE and digital signature.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class RulesOfEngagementResponse(BaseModel):
    success: bool = True
    id: str
    engagement_id: str
    document_html: str
    authorization_clause: str
    methodology_clause: str
    prohibited_actions_clause: str
    client_obligations_clause: str
    liability_clause: str
    confidentiality_clause: str
    is_signed: bool
    created_at: datetime
    signed_at: datetime | None

    class Config:
        from_attributes = True


class DigitalSignatureRequest(BaseModel):
    signed_name: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Full legal name exactly as registered. Must be typed manually.",
    )


class DigitalSignatureResponse(BaseModel):
    success: bool = True
    message: str = "Rules of Engagement signed successfully. Engagement is now authorized."
    signature_id: str
    signed_at: datetime
    pdf_url: str | None
