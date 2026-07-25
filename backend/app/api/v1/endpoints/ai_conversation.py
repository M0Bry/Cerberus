"""
AI Conversation Endpoints — Chat interface with Cerberus AI Agent.
"""

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.ai_conversation import (
    ConversationHistoryResponse,
    ConversationMessageRequest,
    ConversationMessageResponse,
    ConversationSummaryResponse,
)
from app.services.ai_conversation_service import AIConversationService

router = APIRouter()


@router.post("/{engagement_id}/message", response_model=ConversationMessageResponse)
async def send_message(
    engagement_id: str,
    payload: ConversationMessageRequest,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Send a message to the Cerberus AI agent.

    The AI analyzes the response, adapts follow-up questions based
    on the organization type, and builds an internal context model.
    """
    ai_service = AIConversationService(db)
    return await ai_service.process_message(engagement_id, current_user.id, payload)


@router.get("/{engagement_id}/history", response_model=ConversationHistoryResponse)
async def get_history(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get the full conversation history for an engagement."""
    ai_service = AIConversationService(db)
    return await ai_service.get_history(engagement_id, current_user.id)


@router.get("/{engagement_id}/summary", response_model=ConversationSummaryResponse)
async def get_summary(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get the AI-generated engagement summary.

    Returns the structured overview of organization profile,
    business objectives, critical assets, testing scope, etc.
    """
    ai_service = AIConversationService(db)
    return await ai_service.generate_summary(engagement_id, current_user.id)


@router.post("/{engagement_id}/confirm-summary")
async def confirm_summary(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Confirm the AI-generated summary and proceed to
    Scope of Engagement generation.
    """
    ai_service = AIConversationService(db)
    return await ai_service.confirm_summary(engagement_id, current_user.id)


@router.websocket("/{engagement_id}/ws")
async def conversation_websocket(
    websocket: WebSocket,
    engagement_id: str,
):
    """
    WebSocket endpoint for real-time AI conversation.

    Enables live message exchange with streaming AI responses.
    """
    await websocket.accept()
    try:
        while True:
            await websocket.receive_json()  # consume incoming message
            # Process via AI service and send back streaming responses
            await websocket.send_json({
                "type": "ai_response",
                "content": "Processing...",
            })
    except WebSocketDisconnect:
        pass
