"""
AI Conversation Schemas — Request/Response models for AI chat endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class ConversationMessageRequest(BaseModel):
    message: str
    context: dict | None = None


class ConversationMessageResponse(BaseModel):
    success: bool = True
    message_id: str
    ai_response: str
    follow_up_questions: list[str] | None = None
    context_updated: bool = True


class MessageHistoryItem(BaseModel):
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime


class ConversationHistoryResponse(BaseModel):
    success: bool = True
    engagement_id: str
    messages: list[MessageHistoryItem]


class ConversationSummaryResponse(BaseModel):
    success: bool = True
    engagement_id: str
    organization_profile: str
    business_objectives: str
    critical_assets: str
    authorized_targets: str
    out_of_scope: str
    expected_duration: str
    security_priorities: str
    technical_constraints: str
    compliance_considerations: str
    potential_risks: str
    is_confirmed: bool
