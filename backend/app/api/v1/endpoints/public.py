"""Public endpoints (landing stats, health, contact)."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_optional_user
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.contact import ContactMessageCreate, ContactMessageResponse
from app.services.contact_service import ContactService

router = APIRouter()


@router.get("/stats")
async def get_landing_stats():
    return {
        "assessments": 1247,
        "organizations": 389,
        "vulnerabilities": 15632,
        "reports": 892,
    }


@router.post("/contact", response_model=ContactMessageResponse)
async def contact_form(
    payload: ContactMessageCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
    sender: User | None = Depends(get_optional_user),  # noqa: B008
):
    """Public 'Contact Us' submission — stored for the admin inbox.

    If the visitor is logged in, the message is linked to their account
    (admin can see *which registered account* wrote it and can reply,
    which lands on their Notifications page). Otherwise it is stored as
    an unregistered sender.
    """
    service = ContactService(db)
    await service.create_message(
        payload,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        user_id=sender.id if sender else None,
    )
    return ContactMessageResponse()
