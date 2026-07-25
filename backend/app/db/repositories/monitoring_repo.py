"""Monitoring Repository — Data access for monitoring and alerts."""

from sqlalchemy.ext.asyncio import AsyncSession


class MonitoringRepository:
    """Repository for monitoring events, health checks, and blocked IPs."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_alert(self, alert: dict) -> dict:
        """Create a security alert."""
        # In production: store in SecurityAlert table
        return alert

    async def get_active_alerts(self) -> list[dict]:
        """Get all active security alerts."""
        return []

    async def block_ip(
        self, ip: str, reason: str, duration_hours: int = 24
    ) -> dict:
        """Block an IP address."""
        return {"ip": ip, "reason": reason, "duration_hours": duration_hours}

    async def get_blocked_ips(self) -> list[dict]:
        """Get all blocked IPs."""
        return []

    async def record_metric(self, name: str, value: float, unit: str):
        """Record a system metric."""
        pass
