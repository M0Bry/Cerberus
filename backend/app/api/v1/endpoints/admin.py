"""
Admin Endpoints — Platform administration.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminDashboardResponse,
    SystemAuditLogResponse,
    UserManagementListResponse,
)
from app.services.admin_service import AdminService

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
