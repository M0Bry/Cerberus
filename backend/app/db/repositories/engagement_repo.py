"""Engagement Repository — Data access layer for engagement operations."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.engagement import Engagement, EngagementStatus


class EngagementRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, engagement_id: str) -> Engagement | None:
        result = await self.db.execute(
            select(Engagement).where(Engagement.id == engagement_id)
        )
        return result.scalar_one_or_none()

    async def list_by_user(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
    ) -> tuple[list[Engagement], int]:
        query = select(Engagement).where(Engagement.user_id == user_id)
        if status:
            query = query.where(Engagement.status == status)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        count_result = await self.db.execute(count_query)
        count: int = count_result.scalar() or 0

        # Fetch page
        query = (
            query.order_by(Engagement.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all()), count

    async def create(self, engagement: Engagement) -> Engagement:
        self.db.add(engagement)
        await self.db.flush()
        return engagement

    async def update_status(
        self, engagement_id: str, status: EngagementStatus
    ) -> None:
        eng = await self.get_by_id(engagement_id)
        if eng:
            eng.status = status
            await self.db.flush()
