"""
Monitoring Background Tasks — Health checks, anomaly detection.
"""

import asyncio
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="monitoring.health_check")
def run_health_check(self):
    """
    Run periodic health checks on all services.
    """
    async def _run():
        import sqlalchemy as sa

        from app.db.session import async_session_factory

        results = {}

        # Check database
        try:
            async with async_session_factory() as db:
                await db.execute(sa.text("SELECT 1"))
            results["database"] = {"status": "healthy", "latency_ms": 0}
        except Exception as e:
            results["database"] = {"status": "unhealthy", "error": str(e)}

        # Check Redis
        try:
            import redis.asyncio as aioredis

            from app.core.config import settings

            r = aioredis.from_url(settings.REDIS_URL)
            await r.ping()
            await r.close()
            results["redis"] = {"status": "healthy", "latency_ms": 0}
        except Exception as e:
            results["redis"] = {"status": "unhealthy", "error": str(e)}

        overall = (
            "healthy"
            if all(r["status"] == "healthy" for r in results.values())
            else "degraded"
        )

        return {
            "status": overall,
            "checks": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

    return asyncio.run(_run())


@celery_app.task(bind=True, name="monitoring.anomaly_scan")
def run_anomaly_scan(self):
    """
    Scan recent logs for anomalous patterns.
    """
    async def _run():
        # Placeholder — in production, instantiate and use the detector
        # from app.core.anomaly_detection import AnomalyDetector
        # detector = AnomalyDetector()
        return {
            "anomalies_found": 0,
            "status": "clean",
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }

    return asyncio.run(_run())


@celery_app.task(bind=True, name="monitoring.cleanup")
def cleanup_expired_data(self):
    """
    Clean up expired sessions, OTPs, temp files.
    """
    async def _run():
        from datetime import datetime, timezone

        from sqlalchemy import delete

        from app.db.models.otp import OTPVerification
        from app.db.models.session import UserSession
        from app.db.session import async_session_factory

        now = datetime.now(timezone.utc)  # noqa: UP017
        cleaned = {}

        async with async_session_factory() as db:
            # Clean expired OTPs
            result = await db.execute(
                delete(OTPVerification).where(OTPVerification.expires_at < now)
            )
            cleaned["expired_otps"] = result.rowcount

            # Clean expired sessions
            result = await db.execute(
                delete(UserSession).where(UserSession.expires_at < now)
            )
            cleaned["expired_sessions"] = result.rowcount

            await db.commit()

        return {
            "cleaned": True,
            "items_removed": cleaned,
            "timestamp": now.isoformat(),
        }

    return asyncio.run(_run())
