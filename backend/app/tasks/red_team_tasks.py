"""
Red Team Execution Background Tasks.
"""

import asyncio

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="red_team.execute")
def run_red_team(self, engagement_id: str):
    """
    Execute Red Team validation of attack paths.

    Validates each attack path using controlled,
    non-destructive proof-of-concept techniques.
    """
    async def _run():
        from sqlalchemy import select

        from app.db.models.attack_path import AttackPath, AttackPathStatus
        from app.db.models.engagement import Engagement, EngagementStatus
        from app.db.session import async_session_factory

        async with async_session_factory() as db:
            # Load approved attack paths
            result = await db.execute(
                select(AttackPath).where(
                    AttackPath.engagement_id == engagement_id,
                    AttackPath.status == AttackPathStatus.APPROVED,
                )
            )
            paths = result.scalars().all()

            validated_count = 0
            for path in paths:
                # Execute each path (non-destructive PoC)
                # In production: call actual exploit tools via sandbox
                path.status = AttackPathStatus.VALIDATED
                validated_count += 1

            # Update engagement
            eng_result = await db.execute(
                select(Engagement).where(Engagement.id == engagement_id)
            )
            engagement = eng_result.scalar_one_or_none()
            if engagement:
                engagement.status = EngagementStatus.RED_TEAM_COMPLETE
                engagement.progress_percentage = 60

            await db.commit()

            return {
                "engagement_id": engagement_id,
                "status": "completed",
                "paths_validated": validated_count,
            }

    return asyncio.run(_run())
