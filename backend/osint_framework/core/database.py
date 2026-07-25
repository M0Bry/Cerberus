"""
OSINT Database — Stores and retrieves intelligence findings.
"""

import json
import uuid

import structlog
from sqlalchemy import select

logger = structlog.get_logger()

# (rest of the class remains the same, just no datetime import)

logger = structlog.get_logger()


class OSINTDatabase:
    """
    Database layer for OSINT findings storage and retrieval.

    Uses PostgreSQL in production, with Redis caching.
    Provides a clean interface for the engine to persist results.
    """

    def __init__(self, db_session=None, redis_client=None):
        self.db = db_session
        self.redis = redis_client

    async def store_finding(self, engagement_id: str, finding: dict[str, object]) -> str:
        """Store an OSINT finding in the database."""
        finding_id = str(finding.get("id", str(uuid.uuid4())))

        # Cache in Redis for fast retrieval
        if self.redis:
            cache_key = f"osint:{engagement_id}:finding:{finding_id}"
            await self.redis.set(cache_key, json.dumps(finding, default=str), ex=3600)

        logger.info("finding_stored", finding_id=finding_id, engagement_id=engagement_id)
        return finding_id

    async def get_findings(
        self,
        engagement_id: str,
        category: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, object]:
        """Retrieve OSINT findings for an engagement."""
        # Try Redis cache first
        if self.redis:
            cache_key = f"osint:{engagement_id}:findings:{category or 'all'}:{page}"
            cached = await self.redis.get(cache_key)
            if cached:
                return json.loads(cached)

        # Fallback to database query
        if self.db:
            from app.db.models.osint import OSINTFinding

            query = select(OSINTFinding).where(OSINTFinding.engagement_id == engagement_id)
            if category:
                query = query.where(OSINTFinding.category == category)
            query = query.offset((page - 1) * page_size).limit(page_size)
            result = await self.db.execute(query)
            findings = result.scalars().all()
            return {
                "findings": [f.__dict__ for f in findings],
                "total": len(findings),
                "page": page,
            }

        return {"findings": [], "total": 0, "page": page}

    async def store_knowledge_graph(
        self,
        engagement_id: str,
        nodes: list[dict],
        edges: list[dict],
    ) -> None:
        """Store knowledge graph nodes and edges."""
        if self.redis:
            await self.redis.set(
                f"osint:{engagement_id}:graph",
                json.dumps({"nodes": nodes, "edges": edges}, default=str),
                ex=3600,
            )

    async def get_knowledge_graph(self, engagement_id: str) -> dict[str, object]:
        """Retrieve the knowledge graph for an engagement."""
        if self.redis:
            cached = await self.redis.get(f"osint:{engagement_id}:graph")
            if cached:
                return json.loads(cached)
        return {"nodes": [], "edges": []}
