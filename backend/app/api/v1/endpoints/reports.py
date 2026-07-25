"""
Report Endpoints — Generate and download penetration testing reports.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.report import (
    ReportGenerateResponse,
    ReportListResponse,
    ReportResponse,
)
from app.services.report_service import ReportService

router = APIRouter()


@router.post("/{engagement_id}/generate", response_model=ReportGenerateResponse)
async def generate_report(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Generate the final penetration testing report.

    Produces a professional PDF with:
    - Executive Summary
    - Scope of Engagement
    - Assessment Methodology
    - Detailed Findings
    - Remediation Roadmap
    - Overall Security Assessment
    """
    report_service = ReportService(db)
    return await report_service.generate_report(engagement_id, current_user.id)


@router.get("/{engagement_id}", response_model=ReportListResponse)
async def list_reports(
    engagement_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """List all reports for an engagement."""
    report_service = ReportService(db)
    return await report_service.list_reports(engagement_id, current_user.id)


@router.get("/{engagement_id}/{report_id}", response_model=ReportResponse)
async def get_report(
    engagement_id: str,
    report_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get a specific report with full content."""
    report_service = ReportService(db)
    return await report_service.get_report(engagement_id, report_id, current_user.id)


@router.get("/{engagement_id}/{report_id}/download")
async def download_report_pdf(
    engagement_id: str,
    report_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Download the report as a PDF file."""
    report_service = ReportService(db)
    return await report_service.download_pdf(engagement_id, report_id, current_user.id)
