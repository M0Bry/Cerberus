"""
Dashboard Service — Aggregated data for the user dashboard.
"""

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.report import Report
from app.db.models.user import User
from app.db.models.vulnerability import SeverityLevel, Vulnerability
from app.schemas.dashboard import (
    DashboardOverviewResponse,
    DashboardStatItem,
    DashboardStatsResponse,
    RecentAssessmentItem,
)

logger = structlog.get_logger()


class DashboardService:
    """Provides dashboard data aggregation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_overview(self, user_id: str) -> DashboardOverviewResponse:
        """Get full dashboard overview."""

        # Get user info
        user_result = await self.db.execute(select(User).where(User.id == user_id))
        user = user_result.scalar_one_or_none()

        # Get stats
        stats = await self._get_stats(user_id)

        # Get recent assessments
        recent_result = await self.db.execute(
            select(Engagement)
            .where(Engagement.user_id == user_id)
            .order_by(Engagement.created_at.desc())
            .limit(5)
        )
        recent = recent_result.scalars().all()

        recent_items = [
            RecentAssessmentItem(
                id=e.id,
                engagement_number=e.engagement_number,
                project_name=e.project_name,
                organization_name=e.organization_name,
                status=e.status.value,
                progress_percentage=e.progress_percentage,
                risk_level=e.risk_level,
                created_at=e.created_at,
            )
            for e in recent
        ]

        return DashboardOverviewResponse(
            user_name=user.full_name if user else "User",
            organization_name=user.company_name if user else "",
            stats=stats,
            recent_assessments=recent_items,
            last_assessment_date=recent[0].created_at if recent else None,
        )

    async def get_stats(self, user_id: str) -> DashboardStatsResponse:
        """Get dashboard statistics."""
        data = await self._get_stats(user_id)

        return DashboardStatsResponse(
            total_assessments=data[0].value if data else 0,
            completed_assessments=data[1].value if len(data) > 1 else 0,
            running_assessments=data[2].value if len(data) > 2 else 0,
            generated_reports=data[3].value if len(data) > 3 else 0,
            critical_vulnerabilities=data[4].value if len(data) > 4 else 0,
            last_assessment_date=None,
        )

    async def _get_stats(self, user_id: str) -> list:
        """Build the statistics cards."""

        # Total assessments
        total = await self.db.execute(
            select(func.count()).where(Engagement.user_id == user_id)
        )

        # Completed
        completed = await self.db.execute(
            select(func.count()).where(
                Engagement.user_id == user_id,
                Engagement.status == EngagementStatus.COMPLETED,
            )
        )

        # Running
        running = await self.db.execute(
            select(func.count()).where(
                Engagement.user_id == user_id,
                Engagement.status.notin_([
                    EngagementStatus.COMPLETED,
                    EngagementStatus.CANCELLED,
                    EngagementStatus.DRAFT,
                ]),
            )
        )

        # Reports
        reports = await self.db.execute(
            select(func.count()).select_from(Report)
            .join(Engagement)
            .where(Engagement.user_id == user_id)
        )

        # Critical vulns
        critical = await self.db.execute(
            select(func.count()).select_from(Vulnerability)
            .join(Engagement)
            .where(
                Engagement.user_id == user_id,
                Vulnerability.severity == SeverityLevel.CRITICAL,
            )
        )

        return [
            DashboardStatItem(label="Total Assessments", value=total.scalar() or 0),
            DashboardStatItem(label="Completed", value=completed.scalar() or 0),
            DashboardStatItem(label="Running", value=running.scalar() or 0),
            DashboardStatItem(label="Reports", value=reports.scalar() or 0),
            DashboardStatItem(label="Critical Vulns", value=critical.scalar() or 0),
        ]
