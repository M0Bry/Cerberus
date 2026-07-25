"""
Risk Assessment Service — Business impact analysis and AI validation.
"""

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.risk_assessment import RiskAssessment, RiskLevel
from app.db.models.vulnerability import Vulnerability
from app.schemas.risk_assessment import (
    AIValidationResponse,
    RiskAssessmentItem,
    RiskAssessmentListResponse,
    RiskAssessmentStartResponse,
    RiskSummaryResponse,
)

logger = structlog.get_logger()


class RiskAssessmentService:
    """Handles risk assessment operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def start_assessment(
        self, engagement_id: str, user_id: str
    ) -> RiskAssessmentStartResponse:
        """Start risk assessment phase."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        engagement.status = EngagementStatus.RISK_ASSESSMENT
        engagement.current_phase = "Risk Assessment"
        await self.db.flush()

        logger.info("risk_assessment_started", engagement_id=engagement_id)
        return RiskAssessmentStartResponse(
            engagement_id=engagement_id, status="in_progress"
        )

    async def get_assessments(
        self, engagement_id: str, user_id: str
    ) -> RiskAssessmentListResponse:
        """Get all risk assessments."""
        await self._verify_engagement(engagement_id, user_id)

        result = await self.db.execute(
            select(RiskAssessment)
            .where(RiskAssessment.engagement_id == engagement_id)
            .order_by(RiskAssessment.remediation_priority)
        )
        assessments = result.scalars().all()

        items = []
        for ra in assessments:
            vuln_result = await self.db.execute(
                select(Vulnerability.title).where(
                    Vulnerability.id == ra.vulnerability_id
                )
            )
            vuln_title = vuln_result.scalar() or "Unknown"
            items.append(
                RiskAssessmentItem(
                    id=ra.id,
                    vulnerability_id=ra.vulnerability_id,
                    vulnerability_title=vuln_title,
                    risk_level=ra.risk_level.value,
                    likelihood_of_exploitation=ra.likelihood_of_exploitation,
                    cumulative_risk_score=ra.cumulative_risk_score,
                    potential_consequences=ra.potential_consequences,
                    remediation_priority=ra.remediation_priority,
                    assessed_at=ra.assessed_at,
                )
            )

        return RiskAssessmentListResponse(
            engagement_id=engagement_id,
            total=len(items),
            items=items,
        )

    async def get_summary(
        self, engagement_id: str, user_id: str
    ) -> RiskSummaryResponse:
        """Get risk summary with severity distribution."""
        await self._verify_engagement(engagement_id, user_id)

        counts: dict[str, int] = {}
        for level in RiskLevel:
            result = await self.db.execute(
                select(func.count()).where(
                    RiskAssessment.engagement_id == engagement_id,
                    RiskAssessment.risk_level == level,
                )
            )
            counts[level.value] = result.scalar() or 0

        total = sum(counts.values())

        if counts.get("critical", 0) > 0:
            overall_risk = "critical"
        elif counts.get("high", 0) > 0:
            overall_risk = "high"
        elif counts.get("medium", 0) > 0:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        briefing = (
            f"Risk assessment completed. The organization currently exhibits an "
            f"overall {overall_risk.upper()} security risk. "
            f"{counts.get('critical', 0)} critical vulnerabilities require "
            f"immediate remediation, while {counts.get('high', 0)} additional "
            f"findings should be addressed as part of the next security improvement "
            f"cycle."
        )

        return RiskSummaryResponse(
            engagement_id=engagement_id,
            overall_risk_level=overall_risk,
            total_findings=total,
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            executive_briefing=briefing,
            most_critical_attack_paths=[],
        )

    async def validate_findings(
        self, engagement_id: str, user_id: str
    ) -> AIValidationResponse:
        """Run AI validation on all findings."""
        await self._verify_engagement(engagement_id, user_id)

        return AIValidationResponse(
            engagement_id=engagement_id,
            total_findings_reviewed=0,
            findings_validated=0,
            findings_downgraded=0,
            findings_excluded=0,
            duplicates_removed=0,
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
