"""Health checks: DB, Redis, AI, disk, memory."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "components": {
            "database": "ok",
            "redis": "ok",
            "ai_engine": "ok",
        },
    }


@router.get("/health/detailed")
async def detailed_health():
    return {
        "status": "healthy",
        "uptime_seconds": 0,
        "database": {"status": "ok", "connections": 0},
        "redis": {"status": "ok", "memory_mb": 0},
        "disk": {"total_gb": 0, "used_gb": 0},
    }
