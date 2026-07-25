"""
Notification Endpoints — User notifications management.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.notification import (
    MarkReadResponse,
    NotificationListResponse,
)
from app.services.notification_service import NotificationService

router = APIRouter()


@router.get("/", response_model=NotificationListResponse)
async def list_notifications(
    unread_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """List notifications for the current user."""
    notif_service = NotificationService(db)
    return await notif_service.list_notifications(
        current_user.id, unread_only, page, page_size
    )


@router.put("/{notification_id}/read", response_model=MarkReadResponse)
async def mark_as_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Mark a specific notification as read."""
    notif_service = NotificationService(db)
    return await notif_service.mark_as_read(notification_id, current_user.id)


@router.put("/read-all", response_model=MarkReadResponse)
async def mark_all_as_read(
    current_user: User = Depends(get_current_user),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Mark all notifications as read."""
    notif_service = NotificationService(db)
    return await notif_service.mark_all_as_read(current_user.id)
