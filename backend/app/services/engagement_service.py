"""
Engagement Service — Manages penetration testing engagement lifecycle.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.attack_path import AttackPath
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.osint import OSINTFinding
from app.db.models.report import Report
from app.db.models.vulnerability import SeverityLevel, Vulnerability
from app.schemas.engagement import (
    EngagementListResponse,
    EngagementResponse,
    EngagementSummaryResponse,
)

logger = structlog.get_logger()


def _generate_engagement_number() -> str:
    """Generate a unique engagement number (e.g., CER-2026-00001)."""
    year = datetime.now(timezone.utc).year  # noqa: UP017
    random_part = uuid.uuid4().hex[:5].upper()
    return f"CER-{year}-{random_part}"


class EngagementService:
    """Handles engagement CRUD and lifecycle management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_engagement(
        self, user_id: str, data: dict
    ) -> EngagementResponse:
        """Create a new engagement."""
        engagement_id = str(uuid.uuid4())
        engagement_number = _generate_engagement_number()

        engagement = Engagement(
            id=engagement_id,
            engagement_number=engagement_number,
            user_id=user_id,
            project_name=data["project_name"],
            organization_name=data["organization_name"],
            objective=data.get("objective"),
            description=data.get("description"),
            status=EngagementStatus.DRAFT,
            progress_percentage=0,
        )
        self.db.add(engagement)
        await self.db.flush()

        logger.info(
            "engagement_created",
            engagement_id=engagement_id,
            engagement_number=engagement_number,
            user_id=user_id,
        )

        return EngagementResponse.model_validate(engagement)

    async def list_engagements(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        search: str | None = None,
    ) -> EngagementListResponse:
        """List engagements with pagination and filtering."""

        query = select(Engagement).where(Engagement.user_id == user_id)

        if status:
            query = query.where(Engagement.status == status)

        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    Engagement.project_name.ilike(search_term),
                    Engagement.organization_name.ilike(search_term),
                    Engagement.engagement_number.ilike(search_term),
                )
            )

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        query = query.order_by(Engagement.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)
        engagements = result.scalars().all()

        return EngagementListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[EngagementResponse.model_validate(e) for e in engagements],
        )

    async def get_engagement(
        self, engagement_id: str, user_id: str
    ) -> EngagementResponse:
        """Get a specific engagement."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")
        return EngagementResponse.model_validate(engagement)

    async def get_summary(
        self, engagement_id: str, user_id: str
    ) -> EngagementSummaryResponse:
        """Get engagement summary with all phase statistics."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")

        # Count vulnerabilities by severity
        vuln_counts: dict[str, int] = {}
        for sev in SeverityLevel:
            count_result = await self.db.execute(
                select(func.count()).where(
                    Vulnerability.engagement_id == engagement_id,
                    Vulnerability.severity == sev,
                )
            )
            vuln_counts[sev.value] = count_result.scalar() or 0

        # Count OSINT findings
        osint_result = await self.db.execute(
            select(func.count()).where(OSINTFinding.engagement_id == engagement_id)
        )
        osint_count = osint_result.scalar() or 0

        # Count attack paths
        paths_result = await self.db.execute(
            select(func.count()).where(AttackPath.engagement_id == engagement_id)
        )
        paths_count = paths_result.scalar() or 0

        # Count reports
        reports_result = await self.db.execute(
            select(func.count()).where(Report.engagement_id == engagement_id)
        )
        reports_count = reports_result.scalar() or 0

        total_findings = sum(vuln_counts.values())

        return EngagementSummaryResponse(
            engagement_id=engagement_id,
            status=engagement.status.value,
            progress_percentage=engagement.progress_percentage,
            total_findings=total_findings,
            critical_vulnerabilities=vuln_counts.get("critical", 0),
            high_vulnerabilities=vuln_counts.get("high", 0),
            medium_vulnerabilities=vuln_counts.get("medium", 0),
            low_vulnerabilities=vuln_counts.get("low", 0),
            osint_findings_count=osint_count,
            attack_paths_count=paths_count,
            reports_count=reports_count,
            overall_security_score=engagement.overall_security_score,
        )
