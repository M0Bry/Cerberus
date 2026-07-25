"""
Dashboard Endpoints — Aggregated data for the user dashboard.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.dashboard import (
    DashboardOverviewResponse,
    DashboardStatsResponse,
)
from app.services.dashboard_service import DashboardService

router = APIRouter()


@router.get("/overview", response_model=DashboardOverviewResponse)
async def get_overview(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get the full dashboard overview.

    Returns personalized welcome, quick statistics,
    recent assessments, and available services.
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_overview(current_user.id)


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_stats(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get animated dashboard statistics.

    Returns: Total Assessments, Completed, Running,
    Generated Reports, Critical Vulnerabilities, Last Assessment Date.
    """
    dashboard_service = DashboardService(db)
    return await dashboard_service.get_stats(current_user.id)
