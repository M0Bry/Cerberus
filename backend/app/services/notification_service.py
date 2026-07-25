"""
Notification Service — User notification management.
"""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.notification import Notification
from app.schemas.notification import (
    MarkReadResponse,
    NotificationItem,
    NotificationListResponse,
)


class NotificationService:
    """Handles user notification operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_notifications(
        self,
        user_id: str,
        unread_only: bool = False,
        page: int = 1,
        page_size: int = 20,
    ) -> NotificationListResponse:
        """List notifications for a user."""

        query = select(Notification).where(Notification.user_id == user_id)

        if unread_only:
            query = query.where(Notification.is_read.is_(False))

        # Count total
        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        # Count unread
        unread_result = await self.db.execute(
            select(func.count()).where(
                Notification.user_id == user_id,
                Notification.is_read.is_(False),
            )
        )
        unread_count = unread_result.scalar() or 0

        # Paginate
        query = query.order_by(Notification.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)
        notifications = result.scalars().all()

        return NotificationListResponse(
            total=total,
            unread_count=unread_count,
            page=page,
            page_size=page_size,
            items=[NotificationItem.model_validate(n) for n in notifications],
        )

    async def mark_as_read(
        self, notification_id: str, user_id: str
    ) -> MarkReadResponse:
        """Mark a notification as read."""
        result = await self.db.execute(
            select(Notification).where(
                Notification.id == notification_id,
                Notification.user_id == user_id,
            )
        )
        notification = result.scalar_one_or_none()
        if not notification:
            raise NotFoundError("Notification not found")

        notification.is_read = True
        notification.read_at = datetime.now(timezone.utc)  # noqa: UP017
        await self.db.flush()

        return MarkReadResponse()

    async def mark_all_as_read(self, user_id: str) -> MarkReadResponse:
        """Mark all notifications as read."""
        result = await self.db.execute(
            select(Notification).where(
                Notification.user_id == user_id,
                Notification.is_read.is_(False),
            )
        )
        notifications = result.scalars().all()

        now = datetime.now(timezone.utc)  # noqa: UP017
        for n in notifications:
            n.is_read = True
            n.read_at = now

        await self.db.flush()
        return MarkReadResponse()
