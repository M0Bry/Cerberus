"""Monitoring: alerts / incidents / health / blocked IPs."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/dashboard")
async def monitoring_dashboard():
    return {
        "system_health": "healthy",
        "active_alerts": 0,
        "blocked_ips": 0,
        "uptime_percentage": 99.9,
    }


@router.get("/alerts")
async def get_alerts():
    return {"alerts": [], "total": 0}


@router.get("/blocked-ips")
async def get_blocked_ips():
    return {"blocked_ips": [], "total": 0}


@router.get("/incidents")
async def get_incidents():
    return {"incidents": [], "total": 0}


@router.get("/health")
async def get_health():
    return {"status": "healthy"}
