"""
Report Generation Background Tasks.
"""

import asyncio
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="report.generate")
def generate_report_pdf(self, report_id: str):
    """
    Generate a professional PDF report.

    Compiles all findings, evidence, and recommendations
    into a formatted PDF document.
    """
    async def _run():
        from sqlalchemy import func, select

        from app.ai_engine.report_generation.report_builder import ReportBuilder
        from app.db.models.engagement import Engagement, EngagementStatus
        from app.db.models.report import Report, ReportStatus
        from app.db.models.vulnerability import SeverityLevel, Vulnerability
        from app.db.session import async_session_factory

        async with async_session_factory() as db:
            result = await db.execute(
                select(Report).where(Report.id == report_id)
            )
            report = result.scalar_one_or_none()
            if not report:
                return {
                    "report_id": report_id,
                    "status": "error",
                    "message": "Report not found",
                }

            eng_result = await db.execute(
                select(Engagement).where(
                    Engagement.id == report.engagement_id
                )
            )
            engagement = eng_result.scalar_one_or_none()

            counts = {}
            for sev in SeverityLevel:
                count_result = await db.execute(
                    select(func.count()).where(
                        Vulnerability.engagement_id == report.engagement_id,
                        Vulnerability.severity == sev,
                    )
                )
                counts[sev.value] = count_result.scalar()

            builder = ReportBuilder()
            report_data = {
                "engagement_id": report.engagement_id,
                "organization_name": (
                    engagement.organization_name
                    if engagement
                    else "Unknown"
                ),
                "project_name": (
                    engagement.project_name
                    if engagement
                    else "Unknown"
                ),
                "engagement_number": (
                    engagement.engagement_number
                    if engagement
                    else "N/A"
                ),
                "total_findings": sum(counts.values()),
                "critical_count": counts.get("critical", 0),
                "high_count": counts.get("high", 0),
                "medium_count": counts.get("medium", 0),
                "low_count": counts.get("low", 0),
                "security_score": report.overall_security_score,
            }

            generated = await builder.generate_report(report_data)

            report.executive_summary = generated.get(
                "executive_summary", ""
            )
            report.methodology = generated.get("methodology", "")
            report.detailed_findings = generated.get(
                "detailed_findings", ""
            )
            report.remediation_roadmap = generated.get(
                "remediation_roadmap", ""
            )
            report.overall_assessment = generated.get(
                "overall_assessment", ""
            )
            report.status = ReportStatus.GENERATED
            report.pdf_storage_path = generated.get("pdf_path")

            if engagement:
                engagement.status = EngagementStatus.COMPLETED
                engagement.progress_percentage = 100
                engagement.completed_at = datetime.now(timezone.utc)  # noqa: UP017

            await db.commit()

            return {
                "report_id": report_id,
                "status": "completed",
                "pdf_path": report.pdf_storage_path,
            }

    return asyncio.run(_run())
