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

        # Batch-load paid subscriptions + plan names for this page (2 queries
        # total, regardless of page size).
        paid_by_user: dict[str, str | None] = {}
        if users:
            from app.db.models.plan import Plan
            from app.db.models.subscription import Subscription, SubscriptionStatus

            ids = [u.id for u in users]
            sub_rows = (
                await self.db.execute(
                    select(Subscription, Plan.name)
                    .join(Plan, Plan.id == Subscription.plan_id)
                    .where(
                        Subscription.user_id.in_(ids),
                        Subscription.status.in_(
                            (
                                SubscriptionStatus.ACTIVE,
                                SubscriptionStatus.TRIALING,
                                SubscriptionStatus.PAST_DUE,
                            )
                        ),
                    )
                    .order_by(Subscription.created_at.desc())
                )
            ).all()
            for sub, plan_name in sub_rows:
                paid_by_user.setdefault(sub.user_id, plan_name)

        return UserManagementListResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=[
                self._to_admin_user_item(u, paid_by_user.get(u.id))
                for u in users
            ],
        )

    @staticmethod
    def _to_admin_user_item(u: User, plan_name: str | None) -> AdminUserItem:
        """Build an AdminUserItem with the effective access state.

        Mirrors app/services/access_service.py: paid (active / trialing /
        past_due subscription) → suspended (trial expired or recorded
        SUSPENDED) → trial.
        """
        import math
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings

        created = u.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        ends = created + timedelta(days=settings.TRIAL_DAYS)
        now = datetime.now(timezone.utc)  # noqa: UP017
        days_left = max(0, math.ceil((ends - now).total_seconds() / 86400))

        if plan_name is not None:
            access_state = "paid"
        elif u.status.value == "suspended" or now >= ends:
            access_state = "suspended"
        else:
            access_state = "trial"

        return AdminUserItem(
            id=u.id,
            full_name=u.full_name,
            email=u.email,
            company_name=u.company_name,
            role=u.role.value,
            status=u.status.value,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
            plan_name=plan_name,
            access_state=access_state,
            trial_days_left=days_left,
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
