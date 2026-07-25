"""
Red Team Service — Controlled proof-of-concept vulnerability validation.
"""

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.vulnerability import SeverityLevel, Vulnerability
from app.schemas.red_team import (
    RedTeamCompletionResponse,
    RedTeamFindingResponse,
    RedTeamStartResponse,
    RedTeamStatusResponse,
)

logger = structlog.get_logger()


class RedTeamService:
    """Handles Red Team execution operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def start_execution(
        self, engagement_id: str, user_id: str
    ) -> RedTeamStartResponse:
        """Start Red Team execution."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        engagement.status = EngagementStatus.RED_TEAM_IN_PROGRESS
        engagement.current_phase = "Red Team Execution"
        await self.db.flush()

        # Launch background Red Team tasks
        # from app.tasks.red_team_tasks import run_red_team
        # run_red_team.delay(engagement_id)

        logger.info("red_team_started", engagement_id=engagement_id)
        return RedTeamStartResponse(engagement_id=engagement_id, status="in_progress")

    async def get_status(
        self, engagement_id: str, user_id: str
    ) -> RedTeamStatusResponse:
        """Get Red Team execution status."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        # Count vulnerabilities
        vuln_result = await self.db.execute(
            select(func.count()).where(
                Vulnerability.engagement_id == engagement_id
            )
        )
        vuln_count = vuln_result.scalar() or 0

        return RedTeamStatusResponse(
            engagement_id=engagement_id,
            status=engagement.status.value,
            total_paths=0,  # From attack paths count
            completed_paths=0,
            confirmed_vulnerabilities=vuln_count,
            current_path=None,
            progress_percentage=engagement.progress_percentage,
        )

    async def get_findings(
        self, engagement_id: str, user_id: str
    ) -> list[RedTeamFindingResponse]:
        """Get all confirmed vulnerabilities."""
        result = await self.db.execute(
            select(Vulnerability)
            .where(Vulnerability.engagement_id == engagement_id)
            .order_by(Vulnerability.severity)
        )
        vulns = result.scalars().all()
        return [RedTeamFindingResponse.model_validate(v) for v in vulns]

    async def complete(
        self, engagement_id: str, user_id: str
    ) -> RedTeamCompletionResponse:
        """Mark Red Team phase as complete."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        # Count by severity
        counts: dict[str, int] = {}
        for sev in SeverityLevel:
            result = await self.db.execute(
                select(func.count()).where(
                    Vulnerability.engagement_id == engagement_id,
                    Vulnerability.severity == sev,
                )
            )
            counts[sev.value] = result.scalar() or 0

        total = sum(counts.values())

        engagement.status = EngagementStatus.RED_TEAM_COMPLETE
        engagement.current_phase = "Risk Assessment"
        await self.db.flush()

        logger.info("red_team_completed", engagement_id=engagement_id, total=total)

        return RedTeamCompletionResponse(
            engagement_id=engagement_id,
            total_vulnerabilities=total,
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
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
