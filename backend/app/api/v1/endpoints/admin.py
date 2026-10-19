"""
Admin Endpoints — Platform administration.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.db.models.plan import Plan
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminDashboardResponse,
    SystemAuditLogResponse,
    UserManagementListResponse,
)
from app.schemas.contact import (
    ContactMessageItem,
    ContactMessageListResponse,
    ContactReplyRequest,
    ContactReplyResponse,
)
from app.schemas.payment import AdminPlanOut, PlanUpdateRequest
from app.services.admin_service import AdminService
from app.services.contact_service import ContactService

router = APIRouter()


@router.get("/dashboard", response_model=AdminDashboardResponse)
async def get_admin_dashboard(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),                # noqa: B008
):
    """Get admin dashboard with platform-wide statistics."""
    admin_service = AdminService(db)
    return await admin_service.get_dashboard()


@router.get("/users", response_model=UserManagementListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str = Query(None),
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """List all registered users."""
    admin_service = AdminService(db)
    return await admin_service.list_users(page, page_size, search)


@router.get("/audit-logs", response_model=SystemAuditLogResponse)
async def get_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str = Query(None),
    action: str = Query(None),
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Get system audit logs with filtering."""
    admin_service = AdminService(db)
    return await admin_service.get_audit_logs(page, page_size, severity, action)


@router.get("/contact-messages", response_model=ContactMessageListResponse)
async def list_contact_messages(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Admin inbox: public 'Contact Us' submissions."""
    service = ContactService(db)
    return await service.list_messages(page, page_size, unread_only)


@router.patch("/contact-messages/{message_id}", response_model=ContactMessageItem)
async def mark_contact_message_read(
    message_id: str,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Mark a contact message as read."""
    service = ContactService(db)
    return await service.mark_read(message_id)


@router.post(
    "/contact-messages/{message_id}/reply", response_model=ContactReplyResponse
)
async def reply_to_contact_message(
    message_id: str,
    payload: ContactReplyRequest,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Admin replies to a contact message.

    Registered senders receive the reply as a notification on their
    Notifications page.
    """
    service = ContactService(db)
    return await service.reply_message(message_id, payload.message)


@router.get("/plans", response_model=list[AdminPlanOut])
async def list_admin_plans(
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """List ALL plans (active and not), including Stripe link fields.

    This is the operator surface for wiring plans to Stripe prices.
    The public /payments/plans payload never includes these fields.
    """
    result = await db.execute(select(Plan).order_by(Plan.price_cents))
    return result.scalars().all()


@router.put("/plans/{plan_id}", response_model=AdminPlanOut)
async def update_admin_plan(
    plan_id: str,
    payload: PlanUpdateRequest,
    current_user: User = Depends(get_current_admin),  # noqa: B008
    db: AsyncSession = Depends(get_db),               # noqa: B008
):
    """Partial plan update (name, price, active flag, stripe_price_id).

    Setting ``stripe_price_id`` is what makes a plan purchasable:
    checkout returns 503 for plans that are not linked to a Stripe
    price yet.
    """
    result = await db.execute(select(Plan).where(Plan.id == plan_id))
    plan = result.scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found.")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(plan, field, value)
    await db.commit()
    await db.refresh(plan)
    return plan
