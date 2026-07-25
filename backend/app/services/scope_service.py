"""
Scope Service — Manages Scope of Engagement definition and approval.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EngagementError, NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.scope import ScopeAsset, ScopeOfEngagement
from app.schemas.scope import (
    ScopeApprovalResponse,
    ScopeAssetCreate,
    ScopeAssetResponse,
    ScopeResponse,
    ScopeUpdateRequest,
)

logger = structlog.get_logger()


class ScopeService:
    """Handles Scope of Engagement operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_scope(self, engagement_id: str, user_id: str) -> ScopeResponse:
        """Get the scope for an engagement."""
        scope = await self._get_scope(engagement_id, user_id)
        return ScopeResponse.model_validate(scope)

    async def update_scope(
        self, engagement_id: str, user_id: str, payload: ScopeUpdateRequest
    ) -> ScopeResponse:
        """Update scope before approval."""
        scope = await self._get_scope(engagement_id, user_id)

        if scope.approved_at:
            raise EngagementError("Cannot modify approved scope")

        update_data = payload.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scope, field, value)

        await self.db.flush()
        return ScopeResponse.model_validate(scope)

    async def add_asset(
        self, engagement_id: str, user_id: str, payload: ScopeAssetCreate
    ) -> ScopeAssetResponse:
        """Add an asset to the scope."""
        scope = await self._get_scope(engagement_id, user_id)

        asset = ScopeAsset(
            id=str(uuid.uuid4()),
            scope_id=scope.id,
            asset_type=payload.asset_type,
            value=payload.value,
            description=payload.description,
            is_excluded=payload.is_excluded,
            exclusion_reason=payload.exclusion_reason,
        )
        self.db.add(asset)
        await self.db.flush()

        return ScopeAssetResponse.model_validate(asset)

    async def approve_scope(
        self, engagement_id: str, user_id: str
    ) -> ScopeApprovalResponse:
        """Approve the scope and trigger RoE generation."""
        scope = await self._get_scope(engagement_id, user_id)

        scope.approved_at = datetime.now(timezone.utc)  # noqa: UP017

        # Update engagement status
        result = await self.db.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        )
        engagement = result.scalar_one_or_none()
        if engagement:
            engagement.status = EngagementStatus.SCOPE_DEFINED

        await self.db.flush()

        logger.info("scope_approved", engagement_id=engagement_id)

        return ScopeApprovalResponse(scope_id=scope.id)

    async def _get_scope(
        self, engagement_id: str, user_id: str
    ) -> ScopeOfEngagement:
        """Fetch scope with ownership check."""
        # Verify engagement ownership
        eng_result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        if not eng_result.scalar_one_or_none():
            raise NotFoundError("Engagement not found")

        result = await self.db.execute(
            select(ScopeOfEngagement).where(
                ScopeOfEngagement.engagement_id == engagement_id
            )
        )
        scope = result.scalar_one_or_none()
        if not scope:
            raise NotFoundError("Scope not found for this engagement")
        return scope
