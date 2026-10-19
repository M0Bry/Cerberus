"""Trial Sweep — periodic background job that keeps the DB truthful.

Every 30 minutes (and once at startup) it records SUSPENDED for every
non-admin, verified account whose 7-day free trial has expired and which
has no active (or in-grace) subscription.

Users can also be suspended on-demand at the /access and
/engagements endpoints — the sweep is the safety net that guarantees the
database reflects the rule even if the user never logs in again.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select

from app.core.config import settings
from app.db.models.subscription import Subscription, SubscriptionStatus
from app.db.models.user import User, UserRole, UserStatus
from app.db.session import async_session_factory
from app.services.access_service import PAID_SUB_STATUSES, AccessService

logger = structlog.get_logger()

_SWEEP_INTERVAL_SECONDS = 30 * 60


async def run_trial_sweep_once() -> int:
    """Suspend expired-trial users. Returns how many were suspended."""
    now = datetime.now(timezone.utc)  # noqa: UP017
    cutoff = now - timedelta(days=settings.TRIAL_DAYS)

    suspended = 0
    async with async_session_factory() as db:
        candidates = (
            await db.execute(
                select(User).where(
                    User.role == UserRole.USER,
                    User.status == UserStatus.VERIFIED,
                    User.created_at < cutoff,
                )
            )
        ).scalars().all()

        for user in candidates:
            has_paid = (
                await db.execute(
                    select(Subscription.id).where(
                        Subscription.user_id == user.id,
                        Subscription.status.in_(PAID_SUB_STATUSES),
                    ).limit(1)
                )
            ).first()
            if has_paid:
                continue
            await AccessService(db)._suspend(user, now)  # noqa: SLF001
            suspended += 1
        await db.commit()

    if suspended:
        logger.warning("trial_sweep_suspended", count=suspended)
    return suspended


async def trial_sweep_loop() -> None:
    """Runs for the lifetime of the process; never crashes the server."""
    while True:
        try:
            await run_trial_sweep_once()
        except Exception as exc:  # pragma: no cover — defensive
            logger.error("trial_sweep_failed", error=str(exc))
        await asyncio.sleep(_SWEEP_INTERVAL_SECONDS)
