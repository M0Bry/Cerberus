"""
Notification Schemas — Request/Response models for notification endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class NotificationItem(BaseModel):
    id: str
    notification_type: str
    title: str
    message: str
    action_url: str | None
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


class NotificationListResponse(BaseModel):
    success: bool = True
    total: int
    unread_count: int
    page: int
    page_size: int
    items: list[NotificationItem]


class NotificationResponse(BaseModel):
    success: bool = True
    notification: NotificationItem


class MarkReadResponse(BaseModel):
    success: bool = True
    message: str = "Notification(s) marked as read."
