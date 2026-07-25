"""
OSINT Service — Orchestrates OSINT operations using the OSINT Framework.

Integrates the osint_framework with the backend services layer,
providing a clean interface for API endpoints.
"""

import uuid

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.models.engagement import Engagement, EngagementStatus
from app.db.models.osint import (
    FindingCategory,
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
    OSINTFinding,
)
from app.schemas.osint import (
    KnowledgeGraphEdgeItem,
    KnowledgeGraphNodeItem,
    KnowledgeGraphResponse,
    OSINTFindingItem,
    OSINTFindingListResponse,
    OSINTFindingResponse,
    OSINTStartResponse,
    OSINTSummaryResponse,
)

logger = structlog.get_logger()


class OSINTService:
    """
    Handles OSINT phase operations using the osint_framework.

    The OSINT framework is invoked as background tasks via Celery,
    while this service handles database operations and API responses.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def start_osint(
        self, engagement_id: str, user_id: str
    ) -> OSINTStartResponse:
        """Start the OSINT phase for an engagement."""
        engagement = await self._verify_engagement(engagement_id, user_id)

        engagement.status = EngagementStatus.OSINT_IN_PROGRESS
        engagement.current_phase = "OSINT"
        await self.db.flush()

        # Launch background OSINT task using the framework
        # from app.tasks.osint_tasks import run_osint_collection
        # run_osint_collection.delay(engagement_id)
        logger.info("osint_started", engagement_id=engagement_id)

        return OSINTStartResponse(engagement_id=engagement_id, status="in_progress")

    async def get_findings(
        self,
        engagement_id: str,
        user_id: str,
        category: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> OSINTFindingListResponse:
        """Get OSINT findings with optional category filter."""
        await self._verify_engagement(engagement_id, user_id)

        query = select(OSINTFinding).where(
            OSINTFinding.engagement_id == engagement_id
        )

        if category:
            query = query.where(OSINTFinding.category == category)

        count_result = await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        query = query.order_by(OSINTFinding.discovered_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query)
        findings = result.scalars().all()

        return OSINTFindingListResponse(
            engagement_id=engagement_id,
            total=total,
            page=page,
            page_size=page_size,
            items=[OSINTFindingItem.model_validate(f) for f in findings],
        )

    async def get_finding(
        self, engagement_id: str, finding_id: str, user_id: str
    ) -> OSINTFindingResponse:
        """Get a specific OSINT finding with full details."""
        result = await self.db.execute(
            select(OSINTFinding).where(
                OSINTFinding.id == finding_id,
                OSINTFinding.engagement_id == engagement_id,
            )
        )
        finding = result.scalar_one_or_none()
        if not finding:
            raise NotFoundError("Finding not found")
        return OSINTFindingResponse.model_validate(finding)

    async def get_knowledge_graph(
        self, engagement_id: str, user_id: str
    ) -> KnowledgeGraphResponse:
        """Get the dynamically built knowledge graph."""
        await self._verify_engagement(engagement_id, user_id)

        nodes_result = await self.db.execute(
            select(KnowledgeGraphNode).where(
                KnowledgeGraphNode.engagement_id == engagement_id
            )
        )
        edges_result = await self.db.execute(
            select(KnowledgeGraphEdge).where(
                KnowledgeGraphEdge.engagement_id == engagement_id
            )
        )

        nodes = [
            KnowledgeGraphNodeItem.model_validate(n)
            for n in nodes_result.scalars()
        ]
        edges = [
            KnowledgeGraphEdgeItem.model_validate(e)
            for e in edges_result.scalars()
        ]

        return KnowledgeGraphResponse(
            engagement_id=engagement_id,
            nodes=nodes,
            edges=edges,
        )

    async def get_summary(
        self, engagement_id: str, user_id: str
    ) -> OSINTSummaryResponse:
        """Get OSINT phase summary statistics."""
        await self._verify_engagement(engagement_id, user_id)

        category_counts: dict[str, int] = {}
        for cat in FindingCategory:
            result = await self.db.execute(
                select(func.count()).where(
                    OSINTFinding.engagement_id == engagement_id,
                    OSINTFinding.category == cat,
                )
            )
            category_counts[cat.value] = result.scalar() or 0

        total = sum(category_counts.values())

        return OSINTSummaryResponse(
            engagement_id=engagement_id,
            total_findings=total,
            domains_discovered=category_counts.get("technical", 0),
            technologies_identified=category_counts.get("technology", 0),
            employee_profiles=category_counts.get("employee", 0),
            exposed_services=category_counts.get("technical", 0),
            archived_resources=category_counts.get("historical_web", 0),
            leaked_credentials=category_counts.get("credential", 0),
            risk_distribution=category_counts,
        )

    async def store_framework_results(
        self, engagement_id: str, report: object
    ) -> None:
        """Store OSINT Framework results in the database."""
        # Placeholder – dynamic type; suppress attribute errors for now
        for entity in report.entities:  # type: ignore[attr-defined]
            node = KnowledgeGraphNode(
                id=entity.id,
                engagement_id=engagement_id,
                node_type=entity.entity_type,
                label=entity.label,
                properties=entity.properties,
            )
            self.db.add(node)

        for rel in report.relationships:  # type: ignore[attr-defined]
            edge = KnowledgeGraphEdge(
                id=f"{rel.source_id}:{rel.target_id}",
                engagement_id=engagement_id,
                source_node_id=rel.source_id,
                target_node_id=rel.target_id,
                relationship_type=rel.relationship_type,
                weight=rel.weight,
            )
            self.db.add(edge)

        findings = getattr(report, "detailed_findings", {})
        for category, items in findings.get("by_category", {}).items():
            try:
                finding_cat = FindingCategory(category)
            except ValueError:
                finding_cat = FindingCategory.TECHNICAL

            for item in items:
                if isinstance(item, dict):
                    finding = OSINTFinding(
                        id=item.get("metadata", {}).get(
                            "finding_id", str(uuid.uuid4())
                        ),
                        engagement_id=engagement_id,
                        category=finding_cat,
                        title=item.get("data_type", "Unknown"),
                        description=item.get("source", ""),
                        evidence=item.get("evidence"),
                        confidence_score=item.get("confidence", 0.0),
                        raw_data=item.get("raw_data"),
                    )
                    self.db.add(finding)

        await self.db.flush()
        logger.info(
            "osint_results_stored",
            engagement_id=engagement_id,
            entities=len(getattr(report, "entities", [])),
        )

    async def _verify_engagement(
        self, engagement_id: str, user_id: str
    ) -> Engagement:
        """Verify engagement exists and belongs to user."""
        result = await self.db.execute(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == user_id,
            )
        )
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise NotFoundError("Engagement not found")
        return engagement
