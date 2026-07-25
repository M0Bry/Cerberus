"""
Blue Team Defense Endpoints — Three-tier security architecture.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.defense import (
    DefenseDashboardResponse,
    MonitoringStatusResponse,
    SecurityAlertListResponse,
    ThreatIntelligenceResponse,
)
from app.services.defense_service import DefenseService

router = APIRouter()


@router.get("/dashboard", response_model=DefenseDashboardResponse)
async def get_defense_dashboard(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get the Blue Team defense dashboard.

    Returns real-time system health, active security alerts,
    blocked attacks, suspicious sessions, and platform performance.
    """
    defense_service = DefenseService(db)
    return await defense_service.get_dashboard(current_user.id)


@router.get("/alerts", response_model=SecurityAlertListResponse)
async def get_security_alerts(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all security alerts from the three-tier defense system."""
    defense_service = DefenseService(db)
    return await defense_service.get_alerts(current_user.id)


@router.get("/threat-intelligence", response_model=ThreatIntelligenceResponse)
async def get_threat_intelligence(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get current threat intelligence and blocked attack patterns."""
    defense_service = DefenseService(db)
    return await defense_service.get_threat_intelligence(current_user.id)


@router.get("/monitoring", response_model=MonitoringStatusResponse)
async def get_monitoring_status(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get continuous security monitoring status."""
    defense_service = DefenseService(db)
    return await defense_service.get_monitoring_status(current_user.id)
