"""
Attack Planning Background Tasks.
"""

import asyncio

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="attack.build_graph")
def run_attack_planning(self, engagement_id: str):
    """
    Run AI-driven attack path analysis.

    Builds attack graphs from OSINT intelligence and
    generates prioritized attack scenarios.
    """
    async def _run():
        from sqlalchemy import select

        from app.ai_engine.attack_planning.attack_graph import AttackGraphBuilder
        from app.db.models.engagement import Engagement, EngagementStatus
        from app.db.session import async_session_factory

        builder = AttackGraphBuilder()

        async with async_session_factory() as db:
            result = await db.execute(
                select(Engagement).where(Engagement.id == engagement_id)
            )
            engagement = result.scalar_one_or_none()
            if not engagement:
                return {
                    "engagement_id": engagement_id,
                    "status": "error",
                    "message": "Engagement not found",
                }

            findings = []
            graph = {}
            scope = engagement.ai_context_model or ""

            attack_paths = await builder.build_attack_paths(
                findings, graph, scope
            )

            engagement.status = EngagementStatus.ATTACK_PLANNING_COMPLETE
            await db.commit()

            return {
                "engagement_id": engagement_id,
                "status": "completed",
                "attack_paths_generated": (
                    len(attack_paths)
                    if isinstance(attack_paths, list)
                    else 0
                ),
            }

    return asyncio.run(_run())
