"""Access Service — 7-day free trial, paid access, and suspension.

Product rule (owner's spec):
  * Anyone can register and use everything for 7 days — the account is
    "Free" during that window.
  * After the week, the user must choose a plan and pay. Until payment,
    the account is recorded as SUSPENDED in the database.
  * A suspended account can still LOG IN (it must be able to reach Billing
    and pay) but cannot start new assessments.
  * A successful payment lifts the suspension automatically.
  * Admins are never trial-bound.
"""

import math
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.audit_log import AuditAction, AuditLog, AuditSeverity
from app.db.models.notification import Notification, NotificationType
from app.db.models.plan import Plan
from app.db.models.subscription import Subscription, SubscriptionStatus
from app.db.models.user import User, UserRole, UserStatus
from app.schemas.access import AccessInfo

logger = structlog.get_logger()

import uuid as _uuid

# Subscription states that count as "has a paid (or in-grace) subscription".
PAID_SUB_STATUSES = {
    SubscriptionStatus.ACTIVE,
    SubscriptionStatus.TRIALING,
    SubscriptionStatus.PAST_DUE,
}


def trial_ends_at(user: User) -> datetime:
    """The instant this account's free trial ends (created_at + TRIAL_DAYS)."""
    created = user.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created + timedelta(days=settings.TRIAL_DAYS)


class AccessService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── queries ─────────────────────────────────────────────

    async def _paid_subscription(self, user_id: str) -> Subscription | None:
        """Most recent subscription in a paid/grace state (if any)."""
        result = await self.db.execute(
            select(Subscription)
            .where(
                Subscription.user_id == user_id,
                Subscription.status.in_(PAID_SUB_STATUSES),
            )
            .order_by(Subscription.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _plan_name(self, plan_id: str) -> str | None:
        result = await self.db.execute(select(Plan).where(Plan.id == plan_id))
        plan = result.scalar_one_or_none()
        return plan.name if plan else None

    # ─── core ────────────────────────────────────────────────

    async def get_access(self, user: User) -> AccessInfo:
        """Effective access state. Side effect: an expired trial with no
        subscription is PERSISTED as SUSPENDED (the DB is the record)."""
        now = datetime.now(timezone.utc)  # noqa: UP017
        ends = trial_ends_at(user)
        is_admin = user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN)
        days_left = max(0, math.ceil((ends - now).total_seconds() / 86400))

        sub = await self._paid_subscription(user.id)
        if sub:
            return AccessInfo(
                state="paid",
                plan_name=await self._plan_name(sub.plan_id),
                subscription_status=sub.status.value,
                trial_ends_at=ends,
                trial_days_left=days_left,
                is_admin=is_admin,
            )

        if not is_admin and now >= ends:
            await self._suspend(user, now)
            return AccessInfo(
                state="suspended",
                plan_name=None,
                subscription_status=None,
                trial_ends_at=ends,
                trial_days_left=0,
                is_admin=False,
            )

        if is_admin:
            # Admins are never trial-bound; they run the platform, not a plan.
            return AccessInfo(
                state="paid",
                plan_name="Admin",
                subscription_status=None,
                trial_ends_at=ends,
                trial_days_left=days_left,
                is_admin=True,
            )
        return AccessInfo(
            state="trial",
            plan_name=None,
            subscription_status=None,
            trial_ends_at=ends,
            trial_days_left=days_left,
            is_admin=False,
        )

    async def is_suspended(self, user: User) -> bool:
        """Lightweight gate check for operation endpoints (no writes)."""
        if user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
            return False
        sub = await self._paid_subscription(user.id)
        if sub:
            return False
        return datetime.now(timezone.utc) >= trial_ends_at(user)  # noqa: UP017

    # ─── state transitions ───────────────────────────────────

    async def _suspend(self, user: User, now: datetime | None = None) -> None:
        """Record the suspension in the database + tell the user."""
        now = now or datetime.now(timezone.utc)  # noqa: UP017
        if user.status == UserStatus.SUSPENDED:
            return
        user.status = UserStatus.SUSPENDED
        user.updated_at = now

        self.db.add(
            AuditLog(
                user_id=user.id,
                action=AuditAction.SECURITY_ALERT,
                severity=AuditSeverity.WARNING,
                description=(
                    f"Account suspended: free trial ended without subscription "
                    f"(trial ended {trial_ends_at(user).isoformat()})"
                ),
            )
        )
        self.db.add(
            Notification(
                id=str(_uuid.uuid4()),
                user_id=user.id,
                engagement_id=None,
                notification_type=NotificationType.ALERT,
                title="Free trial ended — account suspended",
                message=(
                    "Your 7-day free trial has ended. Your account is suspended "
                    "until a subscription is active. Choose a plan on the Billing "
                    "page to restore access immediately."
                ),
                action_url="/billing",
            )
        )
        await self.db.flush()
        logger.warning("account_suspended_trial_expired", user_id=user.id)

    async def restore_access(self, user: User) -> None:
        """Lift a trial-expiry suspension (called when payment goes active)."""
        if user.status == UserStatus.SUSPENDED:
            user.status = UserStatus.VERIFIED
            user.updated_at = datetime.now(timezone.utc)  # noqa: UP017
            self.db.add(
                Notification(
                    id=str(_uuid.uuid4()),
                    user_id=user.id,
                    engagement_id=None,
                    notification_type=NotificationType.SUCCESS,
                    title="Access restored",
                    message=(
                        "Payment received — your subscription is active and your "
                        "account is no longer suspended. Welcome aboard."
                    ),
                    action_url="/billing",
                )
            )
            await self.db.flush()
            logger.info("account_suspension_lifted", user_id=user.id)
