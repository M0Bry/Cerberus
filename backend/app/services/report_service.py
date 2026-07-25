"""
Report Service — Generates and manages penetration testing reports.
"""

import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.report import Report, ReportStatus
from app.db.models.vulnerability import SeverityLevel, Vulnerability
from app.schemas.report import (
    ReportGenerateResponse,
    ReportItem,
    ReportListResponse,
    ReportResponse,
)

logger = structlog.get_logger()


class ReportService:
    """Handles report generation and management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_report(
        self, engagement_id: str, user_id: str
    ) -> ReportGenerateResponse:
        """Generate a final penetration testing report."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        # Count vulnerabilities
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

        # Calculate security score (0-100, higher is better)
        score = max(
            0,
            100
            - (counts.get("critical", 0) * 25)
            - (counts.get("high", 0) * 15)
            - (counts.get("medium", 0) * 5)
            - (counts.get("low", 0) * 1),
        )

        report = Report(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            title=f"Penetration Testing Report — {engagement.project_name}",
            version="1.0",
            overall_security_score=score,
            total_findings=total,
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            status=ReportStatus.GENERATING,
        )
        self.db.add(report)

        engagement.status = EngagementStatus.REPORT_GENERATING
        engagement.overall_security_score = score
        await self.db.flush()

        # Launch background PDF generation
        # from app.tasks.report_tasks import generate_report_pdf
        # generate_report_pdf.delay(report.id)

        logger.info("report_generation_started", report_id=report.id)

        return ReportGenerateResponse(
            report_id=report.id,
            engagement_id=engagement_id,
            status="generating",
        )

    async def list_reports(
        self, engagement_id: str, user_id: str
    ) -> ReportListResponse:
        """List all reports for an engagement."""
        await self._verify_engagement(engagement_id, user_id)

        result = await self.db.execute(
            select(Report)
            .where(Report.engagement_id == engagement_id)
            .order_by(Report.generated_at.desc())
        )
        reports = result.scalars().all()

        return ReportListResponse(
            engagement_id=engagement_id,
            reports=[ReportItem.model_validate(r) for r in reports],
        )

    async def get_report(
        self, engagement_id: str, report_id: str, user_id: str
    ) -> ReportResponse:
        """Get a specific report."""
        result = await self.db.execute(
            select(Report).where(
                Report.id == report_id,
                Report.engagement_id == engagement_id,
            )
        )
        report = result.scalar_one_or_none()
        if not report:
            raise NotFoundError("Report not found")
        return ReportResponse.model_validate(report)

    async def download_pdf(
        self, engagement_id: str, report_id: str, user_id: str
    ) -> dict:
        """Download report as PDF."""
        result = await self.db.execute(
            select(Report).where(
                Report.id == report_id,
                Report.engagement_id == engagement_id,
            )
        )
        report = result.scalar_one_or_none()
        if not report:
            raise NotFoundError("Report not found")

        if not report.pdf_storage_path:
            raise NotFoundError("PDF not yet generated")

        # Return streaming response
        # from fastapi.responses import StreamingResponse
        # return StreamingResponse(...)

        return {"message": "PDF download will be implemented with file streaming"}

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
