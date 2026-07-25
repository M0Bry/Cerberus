"""
Admin Service — Platform administration operations.
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLog
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.report import Report
from app.db.models.user import User, UserStatus
from app.schemas.admin import (
    AdminDashboardResponse,
    AdminUserItem,
    AuditLogItem,
    SystemAuditLogResponse,
    UserManagementListResponse,
)


class AdminService:
    """Handles admin operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_dashboard(self) -> AdminDashboardResponse:
        """Get admin dashboard with platform-wide statistics."""

        total_users = (
            await self.db.execute(select(func.count()).select_from(User))
        ).scalar() or 0

        active_users = (
            await self.db.execute(
                select(func.count())
                .select_from(User)
                .where(User.status == UserStatus.VERIFIED)
            )
        ).scalar() or 0

        total_engagements = (
            await self.db.execute(select(func.count()).select_from(Engagement))
        ).scalar() or 0

        active_engagements = (
            await self.db.execute(
                select(func.count())
                .select_from(Engagement)
                .where(
                    Engagement.status.notin_([
                        EngagementStatus.COMPLETED,
                        EngagementStatus.CANCELLED,
                        EngagementStatus.DRAFT,
                    ])
                )
            )
        ).scalar() or 0

        total_reports = (
            await self.db.execute(select(func.count()).select_from(Report))
        ).scalar() or 0

        return AdminDashboardResponse(
            total_users=total_users,
            active_users=active_users,
            total_engagements=total_engagements,
            active_engagements=active_engagements,
            total_reports=total_reports,
            system_health="healthy",
        )

    async def list_users(
        self, page: int = 1, page_size: int = 50, search: str | None = None
    ) -> UserManagementListResponse:
        """List all users with pagination."""

        query = select(User)

        if search:
            search_term = f"%{search}%"
            query = query.where(
                User.full_name.ilike(search_term) | User.email.ilike(search_term)
            )

        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        query = query.order_by(User.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)
        users = result.scalars().all()

        return UserManagementListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[
                AdminUserItem(
                    id=u.id,
                    full_name=u.full_name,
                    email=u.email,
                    company_name=u.company_name,
                    role=u.role.value,
                    status=u.status.value,
                    created_at=u.created_at,
                    last_login_at=u.last_login_at,
                )
                for u in users
            ],
        )

    async def get_audit_logs(
        self,
        page: int = 1,
        page_size: int = 50,
        severity: str | None = None,
        action: str | None = None,
    ) -> SystemAuditLogResponse:
        """Get system audit logs."""

        query = select(AuditLog)

        if severity:
            query = query.where(AuditLog.severity == severity)
        if action:
            query = query.where(AuditLog.action == action)

        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        query = query.order_by(AuditLog.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)
        logs = result.scalars().all()

        return SystemAuditLogResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[AuditLogItem.model_validate(log) for log in logs],
        )
