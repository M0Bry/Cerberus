"""Contact Message schemas — public form + admin views."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class ContactMessageCreate(BaseModel):
    """Public 'Contact Us' form payload (contract with the landing page)."""

    name: str = Field(..., min_length=2, max_length=120)
    email: EmailStr
    subject: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., min_length=10, max_length=5000)

    @field_validator("name", "subject", "message")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class ContactMessageResponse(BaseModel):
    success: bool = True
    message: str = "Thank you — your message has been sent."


class ContactMessageItem(BaseModel):
    """Admin view of a single message."""

    id: str
    name: str
    email: str
    subject: str
    message: str
    # Registered-account link (None → unregistered sender from the landing).
    user_id: str | None
    registered: bool
    reply: str | None = None
    replied_at: datetime | None = None
    ip_address: str | None
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ContactReplyRequest(BaseModel):
    """Admin reply to a contact message."""

    message: str = Field(..., min_length=5, max_length=5000)

    @field_validator("message")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class ContactReplyResponse(BaseModel):
    success: bool = True
    message: ContactMessageItem
    # "notification" (registered user) | "email" (guest) | "none" (guest,
    # email failed — the reply is still stored)
    delivery: str
    delivery_note: str | None = None


class ContactMessageListResponse(BaseModel):
    success: bool = True
    items: list[ContactMessageItem]
    total: int
    unread: int
    page: int
    page_size: int
