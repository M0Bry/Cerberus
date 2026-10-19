"""
Blue Team Defense Endpoints — Three-tier security architecture.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.defense import (
    AnomalyStatusResponse,
    BlockedIPListResponse,
    BlockIPRequest,
    BlockIPResponse,
    DefenseDashboardResponse,
    DefenseMetricsResponse,
    IncidentListResponse,
    MonitoringStatusResponse,
    SecurityAlertListResponse,
    ThreatIntelligenceResponse,
    UnblockIPResponse,
)
from app.services.defense_service import DefenseService

router = APIRouter()


# ─── Dashboard ────────────────────────────────────────────────

@router.get("/dashboard", response_model=DefenseDashboardResponse)
async def get_defense_dashboard(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get the Blue Team defense dashboard.

    Returns real-time system health, active security alerts,
    blocked attacks, suspicious sessions, and platform performance.
    """
    defense_service = DefenseService(db)
    return await defense_service.get_dashboard(current_user.id)


# ─── Metrics ──────────────────────────────────────────────────

@router.get("/metrics", response_model=DefenseMetricsResponse)
async def get_defense_metrics_endpoint(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """
    Get raw defense middleware metrics.

    Returns counters for requests inspected, threats blocked,
    rate limits, input validation, abuse, and behavioral anomalies.
    """
    defense_service = DefenseService(db)
    return await defense_service.get_metrics(current_user.id)


# ─── Alerts ───────────────────────────────────────────────────

@router.get("/alerts", response_model=SecurityAlertListResponse)
async def get_security_alerts(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all security alerts from the three-tier defense system."""
    defense_service = DefenseService(db)
    return await defense_service.get_alerts(current_user.id)


# ─── Threat Intelligence ──────────────────────────────────────

@router.get("/threat-intelligence", response_model=ThreatIntelligenceResponse)
async def get_threat_intelligence(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get current threat intelligence and blocked attack patterns."""
    defense_service = DefenseService(db)
    return await defense_service.get_threat_intelligence(current_user.id)


# ─── Monitoring ───────────────────────────────────────────────

@router.get("/monitoring", response_model=MonitoringStatusResponse)
async def get_monitoring_status(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get continuous security monitoring status."""
    defense_service = DefenseService(db)
    return await defense_service.get_monitoring_status(current_user.id)


# ─── Blocked IPs ──────────────────────────────────────────────

@router.get("/blocked-ips", response_model=BlockedIPListResponse)
async def get_blocked_ips(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all currently blocked IPs."""
    defense_service = DefenseService(db)
    return await defense_service.get_blocked_ips()


@router.post(
    "/block-ip",
    response_model=BlockIPResponse,
    status_code=status.HTTP_201_CREATED,
)
async def block_ip(
    request: BlockIPRequest,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Manually block an IP address."""
    defense_service = DefenseService(db)
    return await defense_service.block_ip(
        ip=request.ip,
        duration_seconds=request.duration_seconds,
        reason=request.reason,
    )


@router.post("/unblock-ip", response_model=UnblockIPResponse)
async def unblock_ip(
    request: BlockIPRequest,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Unblock an IP address."""
    defense_service = DefenseService(db)
    return await defense_service.unblock_ip(request.ip)


# ─── Incidents ────────────────────────────────────────────────

@router.get("/incidents", response_model=IncidentListResponse)
async def get_incidents(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get all security incidents."""
    defense_service = DefenseService(db)
    return await defense_service.get_incidents()


# ─── Anomaly Status ───────────────────────────────────────────

@router.get("/anomaly-status/{ip}", response_model=AnomalyStatusResponse)
async def get_anomaly_status(
    ip: str,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get anomaly detection status for a specific IP."""
    defense_service = DefenseService(db)
    return await defense_service.get_anomaly_status(ip)