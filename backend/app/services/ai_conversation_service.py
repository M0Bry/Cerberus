"""
AI Conversation Service — Manages the AI agent conversation for engagement setup.
"""

import json
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai_engine.conversation import CerberusAIConversation
from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.schemas.ai_conversation import (
    ConversationHistoryResponse,
    ConversationMessageRequest,
    ConversationMessageResponse,
    ConversationSummaryResponse,
    MessageHistoryItem,
)

logger = structlog.get_logger()


class AIConversationService:
    """Manages AI conversation for engagement requirement gathering."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_engine = CerberusAIConversation()

    async def _get_engagement(self, engagement_id: str, user_id: str) -> Engagement:
        """Fetch engagement or raise error."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")
        return engagement

    async def process_message(
        self,
        engagement_id: str,
        user_id: str,
        payload: ConversationMessageRequest,
    ) -> ConversationMessageResponse:
        """Process a user message and generate AI response."""

        engagement = await self._get_engagement(engagement_id, user_id)

        # Load existing conversation history
        history = self._load_history(engagement)

        # Append user message
        history.append({
            "role": "user",
            "content": payload.message,
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        })

        # Generate AI response using the engine
        ai_result = await self.ai_engine.generate_response(
            history=history,
            context=engagement.ai_context_model,
            organization_type=self._extract_org_type(history),
        )

        # Append AI response
        message_id = str(uuid.uuid4())
        history.append({
            "role": "assistant",
            "content": ai_result["response"],
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        })

        # Save back to engagement
        engagement.conversation_history = json.dumps(history)
        if ai_result.get("updated_context"):
            engagement.ai_context_model = json.dumps(ai_result["updated_context"])

        await self.db.flush()

        return ConversationMessageResponse(
            message_id=message_id,
            ai_response=ai_result["response"],
            follow_up_questions=ai_result.get("follow_up_questions"),
            context_updated=bool(ai_result.get("updated_context")),
        )

    async def get_history(
        self, engagement_id: str, user_id: str
    ) -> ConversationHistoryResponse:
        """Get full conversation history."""
        engagement = await self._get_engagement(engagement_id, user_id)
        history = self._load_history(engagement)

        messages = [
            MessageHistoryItem(
                role=msg["role"],
                content=msg["content"],
                timestamp=datetime.fromisoformat(msg["timestamp"]),
            )
            for msg in history
        ]

        return ConversationHistoryResponse(
            engagement_id=engagement_id,
            messages=messages,
        )

    async def generate_summary(
        self, engagement_id: str, user_id: str
    ) -> ConversationSummaryResponse:
        """Generate AI summary of the engagement requirements."""
        engagement = await self._get_engagement(engagement_id, user_id)
        history = self._load_history(engagement)

        summary = await self.ai_engine.generate_summary(
            history=history,
            context=engagement.ai_context_model,
        )

        return ConversationSummaryResponse(
            engagement_id=engagement_id,
            organization_profile=summary.get("organization_profile", ""),
            business_objectives=summary.get("business_objectives", ""),
            critical_assets=summary.get("critical_assets", ""),
            authorized_targets=summary.get("authorized_targets", ""),
            out_of_scope=summary.get("out_of_scope", ""),
            expected_duration=summary.get("expected_duration", ""),
            security_priorities=summary.get("security_priorities", ""),
            technical_constraints=summary.get("technical_constraints", ""),
            compliance_considerations=summary.get("compliance_considerations", ""),
            potential_risks=summary.get("potential_risks", ""),
            is_confirmed=False,
        )

    async def confirm_summary(
        self, engagement_id: str, user_id: str
    ) -> dict:
        """Confirm summary and transition to scope generation."""
        engagement = await self._get_engagement(engagement_id, user_id)
        engagement.status = EngagementStatus.SCOPE_DEFINED
        await self.db.flush()

        return {
            "success": True,
            "message": "Summary confirmed. Scope of Engagement will be generated.",
            "next_step": "scope_generation",
        }

    def _load_history(self, engagement: Engagement) -> list[dict]:
        """Load conversation history from engagement."""
        if engagement.conversation_history:
            return json.loads(engagement.conversation_history)
        return []

    def _extract_org_type(self, history: list[dict]) -> str:
        """Extract organization type from conversation for adaptive questioning."""
        for msg in reversed(history):
            if msg["role"] == "user":
                content = msg["content"].lower()
                if any(w in content for w in ["bank", "financial", "fintech"]):
                    return "financial"
                if any(w in content for w in ["health", "hospital", "medical"]):
                    return "healthcare"
                if any(w in content for w in ["software", "dev", "tech", "saas"]):
                    return "technology"
                if any(w in content for w in ["ecommerce", "shop", "retail"]):
                    return "ecommerce"
        return "general"
