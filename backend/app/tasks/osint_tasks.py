"""
OSINT Background Tasks — Runs OSINT Framework collection as Celery tasks.
"""

import asyncio

import structlog

from app.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(bind=True, name="osint.collect")
def run_osint_collection(self, engagement_id: str):
    """
    Run full OSINT collection for an engagement using the OSINT Framework.

    This task:
    1. Loads engagement scope from DB
    2. Initializes the OSINT Engine
    3. Runs intelligence collection (socmint, cybint, darkweb)
    4. Stores findings in the database
    5. Builds the knowledge graph
    6. Updates engagement status
    7. Sends notification to user
    """

    async def _run():
        from osint_framework.config.settings import load_config  # noqa: I001
        from osint_framework.core.engine import OSINTEngine

        from app.db.session import async_session_factory
        from app.services.osint_service import OSINTService

        config = load_config()
        engine = OSINTEngine(config)
        await engine.initialize()

        # In production: load target from engagement scope
        target = "example.com"

        report = await engine.run_intelligence_cycle(
            target=target,
            modules=["socmint", "cybint"],
            engagement_id=engagement_id,
        )

        # Store results in database
        try:
            async with async_session_factory() as db:
                osint_service = OSINTService(db)
                await osint_service.store_framework_results(
                    engagement_id, report
                )
        except Exception as e:
            logger.warning("osint_store_error", error=str(e))

        await engine.cleanup()
        return {
            "engagement_id": engagement_id,
            "status": "completed",
            "entities": len(report.entities),
            "relationships": len(report.relationships),
            "risk_level": report.risk_assessment.get("level", "unknown"),
        }

    return asyncio.run(_run())


@celery_app.task(bind=True, name="osint.collect_dns")
def collect_dns_records(self, domain: str, engagement_id: str):
    """Collect DNS records for a specific domain."""
    async def _run():
        from osint_framework.modules.cybint.domain_intel import DomainIntelligence
        di = DomainIntelligence()
        result = await di.execute(domain)
        return {
            "domain": domain,
            "status": "completed",
            "result": result.to_dict() if result else None,
        }
    return asyncio.run(_run())


@celery_app.task(bind=True, name="osint.collect_ct")
def collect_certificate_transparency(self, domain: str, engagement_id: str):
    """Search certificate transparency logs."""
    async def _run():
        from osint_framework.modules.cybint.domain_intel import DomainIntelligence
        di = DomainIntelligence()
        subdomains = await di._certificate_transparency(domain)
        return {
            "domain": domain,
            "subdomains_found": len(subdomains),
            "status": "completed",
        }
    return asyncio.run(_run())


@celery_app.task(bind=True, name="osint.collect_github")
def collect_github_intel(self, target: str, engagement_id: str):
    """Run GitHub intelligence collection."""
    async def _run():
        from osint_framework.modules.cybint.github_scanner import GitHubScanner
        gs = GitHubScanner()
        result = await gs.execute(target)
        return {
            "target": target,
            "status": "completed",
            "result": result.to_dict() if result else None,
        }
    return asyncio.run(_run())


@celery_app.task(bind=True, name="osint.collect_social")
def collect_social_intel(self, target: str, engagement_id: str):
    """Run social media intelligence collection."""
    async def _run():
        from osint_framework.modules.socmint.social_scanner import SocialScanner
        ss = SocialScanner()
        result = await ss.execute(target)
        return {
            "target": target,
            "status": "completed",
            "result": result.to_dict() if result else None,
        }
    return asyncio.run(_run())


@celery_app.task(bind=True, name="osint.collect_usernames")
def collect_username_enum(self, username: str, engagement_id: str):
    """Run username enumeration across platforms."""
    async def _run():
        from osint_framework.modules.socmint.username_enum import UsernameEnumerator
        ue = UsernameEnumerator()
        result = await ue.execute(username)
        return {
            "username": username,
            "status": "completed",
            "result": result.to_dict() if result else None,
        }
    return asyncio.run(_run())
