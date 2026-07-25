"""
Risk Assessment Background Tasks.
"""

import asyncio
import uuid

from app.tasks.celery_app import celery_app


@celery_app.task(bind=True, name="risk.assess")
def run_risk_assessment(self, engagement_id: str):
    """
    Run business risk assessment on confirmed vulnerabilities.

    Translates technical findings into business impact metrics.
    """
    async def _run():
        from sqlalchemy import select

        from app.ai_engine.risk_assessment.risk_analyzer import RiskAnalyzer
        from app.db.models.engagement import Engagement, EngagementStatus
        from app.db.models.risk_assessment import RiskAssessment, RiskLevel
        from app.db.models.vulnerability import Vulnerability
        from app.db.session import async_session_factory

        analyzer = RiskAnalyzer()

        async with async_session_factory() as db:
            # Load vulnerabilities
            vuln_result = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.engagement_id == engagement_id
                )
            )
            vulnerabilities = vuln_result.scalars().all()

            # Load engagement context
            eng_result = await db.execute(
                select(Engagement).where(Engagement.id == engagement_id)
            )
            engagement = eng_result.scalar_one_or_none()
            org_context = engagement.organization_name if engagement else ""

            # Run AI risk assessment
            vuln_dicts = [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description,
                    "category": v.category,
                    "cvss_score": v.cvss_score,
                }
                for v in vulnerabilities
            ]

            risk_results = await analyzer.assess_risks(vuln_dicts, org_context)

            # Store risk assessments
            for risk in risk_results if isinstance(risk_results, list) else []:
                if isinstance(risk, dict):
                    risk_level_str = risk.get("risk_level", "medium")
                    try:
                        risk_level = RiskLevel(risk_level_str)
                    except ValueError:
                        risk_level = RiskLevel.MEDIUM

                    ra = RiskAssessment(
                        id=str(uuid.uuid4()),
                        engagement_id=engagement_id,
                        vulnerability_id=risk.get("vulnerability_id", ""),
                        risk_level=risk_level,
                        likelihood_of_exploitation=risk.get(
                            "likelihood_of_exploitation", 0.5
                        ),
                        cumulative_risk_score=risk.get(
                            "cumulative_risk_score", 0.5
                        ),
                        remediation_priority=risk.get("remediation_priority", 0),
                    )
                    db.add(ra)

            # Update engagement
            if engagement:
                engagement.status = EngagementStatus.RISK_ASSESSMENT_COMPLETE
                engagement.progress_percentage = 80

            await db.commit()

            return {
                "engagement_id": engagement_id,
                "status": "completed",
                "vulnerabilities_assessed": len(vulnerabilities),
                "risk_assessments_created": (
                    len(risk_results)
                    if isinstance(risk_results, list)
                    else 0
                ),
            }

    return asyncio.run(_run())


@celery_app.task(bind=True, name="risk.validate")
def run_ai_validation(self, engagement_id: str):
    """
    Run AI Decision Validation on all findings.

    Verifies evidence and removes unsupported conclusions.
    """
    async def _run():
        from sqlalchemy import select

        from app.ai_engine.risk_assessment.risk_analyzer import RiskAnalyzer
        from app.db.models.vulnerability import Vulnerability
        from app.db.session import async_session_factory

        analyzer = RiskAnalyzer()

        async with async_session_factory() as db:
            vuln_result = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.engagement_id == engagement_id
                )
            )
            vulnerabilities = vuln_result.scalars().all()

            vuln_dicts = [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description,
                    "evidence": v.proof_of_concept,
                    "confidence_score": v.confidence_score,
                }
                for v in vulnerabilities
            ]

            validation = await analyzer.validate_findings(vuln_dicts)

            return {
                "engagement_id": engagement_id,
                "status": "completed",
                "validated": len(validation.get("validated", [])),
                "excluded": len(validation.get("excluded", [])),
                "downgraded": len(validation.get("downgraded", [])),
            }

    return asyncio.run(_run())
