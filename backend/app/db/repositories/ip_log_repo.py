"""ip_log Repository — Data access for ip_log operations."""

from sqlalchemy.ext.asyncio import AsyncSession


class IpLogRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, id: str):
        return None

    async def list_by_engagement(self, engagement_id: str, limit: int = 100):
        return []

    async def create(self, entity):
        self.db.add(entity)
        await self.db.flush()
        return entity
