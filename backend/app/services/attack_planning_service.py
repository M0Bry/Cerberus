"""
Attack Planning Service — AI-driven attack path analysis.
"""

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.attack_path import AttackPath, AttackPathStatus
from app.db.models.engagement import Engagement, EngagementStatus
from app.schemas.attack_path import (
    AttackPathItem,
    AttackPathListResponse,
    AttackPathResponse,
    AttackPathStepItem,
    AttackPlanApprovalResponse,
    AttackPlanningStartResponse,
)

logger = structlog.get_logger()


class AttackPlanningService:
    """Handles attack planning and analysis operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def start_analysis(
        self, engagement_id: str, user_id: str
    ) -> AttackPlanningStartResponse:
        """Start attack planning analysis."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        engagement.status = EngagementStatus.ATTACK_PLANNING
        engagement.current_phase = "Attack Planning"
        await self.db.flush()

        # Launch background attack analysis
        # from app.tasks.attack_tasks import run_attack_planning
        # run_attack_planning.delay(engagement_id)

        logger.info("attack_planning_started", engagement_id=engagement_id)
        return AttackPlanningStartResponse(
            engagement_id=engagement_id, status="in_progress"
        )

    async def get_attack_paths(
        self, engagement_id: str, user_id: str
    ) -> AttackPathListResponse:
        """Get all attack paths."""
        await self._verify_engagement(engagement_id, user_id)

        result = await self.db.execute(
            select(AttackPath)
            .where(AttackPath.engagement_id == engagement_id)
            .order_by(AttackPath.priority)
        )
        paths = result.scalars().all()

        return AttackPathListResponse(
            engagement_id=engagement_id,
            total=len(paths),
            items=[AttackPathItem.model_validate(p) for p in paths],
        )

    async def get_attack_path(
        self, engagement_id: str, path_id: str, user_id: str
    ) -> AttackPathResponse:
        """Get a specific attack path with steps."""
        result = await self.db.execute(
            select(AttackPath).where(
                AttackPath.id == path_id,
                AttackPath.engagement_id == engagement_id,
            )
        )
        path = result.scalar_one_or_none()
        if not path:
            raise NotFoundError("Attack path not found")

        steps = [AttackPathStepItem.model_validate(s) for s in path.steps]

        response = AttackPathResponse.model_validate(path)
        response.steps = steps
        return response

    async def approve_plan(
        self, engagement_id: str, user_id: str
    ) -> AttackPlanApprovalResponse:
        """Approve attack plan and begin Red Team execution."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        # Count approved paths
        count_result = await self.db.execute(
            select(func.count()).where(
                AttackPath.engagement_id == engagement_id,
                AttackPath.status == AttackPathStatus.APPROVED,
            )
        )
        approved = count_result.scalar() or 0  # Ensure int, not None

        engagement.status = EngagementStatus.ATTACK_PLANNING_COMPLETE
        await self.db.flush()

        logger.info(
            "attack_plan_approved", engagement_id=engagement_id, paths=approved
        )

        return AttackPlanApprovalResponse(
            engagement_id=engagement_id,
            approved_paths=approved,
        )

    async def _verify_engagement(
        self, engagement_id: str, user_id: str
    ) -> Engagement:
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
