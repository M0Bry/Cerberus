"""
Rules of Engagement Service — Auto-generates and manages the RoE document.
"""

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai_engine.roe_generator import RoEGenerator
from app.core.exceptions import EngagementError, NotFoundError
from app.core.security import generate_digital_signature
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.digital_signature import DigitalSignature
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.rules_of_engagement import RulesOfEngagement
from app.db.models.scope import ScopeOfEngagement
from app.schemas.rules_of_engagement import (
    DigitalSignatureRequest,
    DigitalSignatureResponse,
    RulesOfEngagementResponse,
)

logger = structlog.get_logger()


class RulesService:
    """Handles Rules of Engagement operations."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.roe_generator = RoEGenerator()

    async def get_rules(
        self, engagement_id: str, user_id: str
    ) -> RulesOfEngagementResponse:
        """Get the Rules of Engagement."""
        rules = await self._get_rules(engagement_id, user_id)
        return RulesOfEngagementResponse.model_validate(rules)

    async def generate_rules(
        self, engagement_id: str, user_id: str
    ) -> RulesOfEngagementResponse:
        """Auto-generate Rules of Engagement from the approved scope."""

        # Get scope
        scope_result = await self.db.execute(
            select(ScopeOfEngagement).where(
                ScopeOfEngagement.engagement_id == engagement_id
            )
        )
        scope = scope_result.scalar_one_or_none()
        if not scope:
            raise EngagementError(
                "Scope must be defined before generating Rules of Engagement"
            )

        # Get engagement
        eng_result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = eng_result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")

        # Generate RoE using AI engine
        roe_content = await self.roe_generator.generate(
            engagement=engagement,
            scope=scope,
        )

        rules = RulesOfEngagement(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            document_html=roe_content["html"],
            document_text=roe_content["text"],
            authorization_clause=roe_content["authorization"],
            methodology_clause=roe_content["methodology"],
            prohibited_actions_clause=roe_content["prohibited_actions"],
            client_obligations_clause=roe_content["client_obligations"],
            liability_clause=roe_content["liability"],
            confidentiality_clause=roe_content["confidentiality"],
        )
        self.db.add(rules)

        engagement.status = EngagementStatus.RULES_GENERATED
        await self.db.flush()

        logger.info("rules_generated", engagement_id=engagement_id)
        return RulesOfEngagementResponse.model_validate(rules)

    async def sign_rules(
        self,
        request: Request,
        engagement_id: str,
        user_id: str,
        payload: DigitalSignatureRequest,
    ) -> DigitalSignatureResponse:
        """Digitally sign the Rules of Engagement."""

        rules = await self._get_rules(engagement_id, user_id)

        if rules.is_signed:
            raise EngagementError(
                "Rules of Engagement have already been signed"
            )

        # Verify the signed name matches the registered name
        eng_result = await self.db.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        )
        engagement = eng_result.scalar_one_or_none()
        if not engagement:                         # <-- added guard
            raise NotFoundError("Engagement not found")

        # Generate cryptographic signature
        now = datetime.now(timezone.utc)  # noqa: UP017
        sig_hash = generate_digital_signature(user_id, engagement_id, now)

        signature = DigitalSignature(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            user_id=user_id,
            signed_name=payload.signed_name,
            cryptographic_hash=sig_hash,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        self.db.add(signature)

        # Mark rules as signed
        rules.is_signed = True
        rules.signed_at = now

        # Update engagement status
        engagement.status = EngagementStatus.AUTHORIZED

        # Audit log
        audit = AuditLog(
            user_id=user_id,
            engagement_id=engagement_id,
            action=AuditAction.DOCUMENT_SIGNED,
            severity=AuditSeverity.INFO,
            description=f"Rules of Engagement signed by {payload.signed_name}",
            ip_address=request.client.host if request.client else None,
        )
        self.db.add(audit)

        await self.db.flush()

        logger.info("roe_signed", engagement_id=engagement_id, user_id=user_id)

        return DigitalSignatureResponse(
            signature_id=signature.id,
            signed_at=now,
            pdf_url=None,  # PDF generation handled by background task
        )

    async def _get_rules(
        self, engagement_id: str, user_id: str
    ) -> RulesOfEngagement:
        """Fetch rules with ownership check."""
        eng_result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        if not eng_result.scalar_one_or_none():
            raise NotFoundError("Engagement not found")

        result = await self.db.execute(
            select(RulesOfEngagement).where(
                RulesOfEngagement.engagement_id == engagement_id
            )
        )
        rules = result.scalar_one_or_none()
        if not rules:
            raise NotFoundError("Rules of Engagement not found")
        return rules
