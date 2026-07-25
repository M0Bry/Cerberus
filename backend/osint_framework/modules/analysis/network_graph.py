"""
Network Graph — Builds and analyzes relationship networks from OSINT data.
Uses NetworkX for graph operations and generates interactive visualizations.
"""

import structlog

from osint_framework.core import IntelligenceResult, Relationship
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class NetworkAnalyzer(OSINTPlugin):
    """… (same docstring) …"""

    def __init__(self):
        super().__init__()
        self.name = "network_analyzer"
        self.description = "Relationship network analysis and visualization"
        self.category = "analysis"

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        entities = kwargs.get("entities", [])
        relationships = kwargs.get("relationships", [])

        logger.info(
            "network_analysis_started",
            entities=len(entities),
            relationships=len(relationships),
        )

        adjacency: dict[str, list[Relationship]] = {}
        for rel in relationships:
            adjacency.setdefault(rel.source_id, []).append(rel)

        stats = {
            "nodes": len(entities),
            "edges": len(relationships),
            "density": len(relationships) / max(1, (len(entities) * (len(entities) - 1) / 2)),
        }

        entity_connections: dict[str, int] = {}
        for rel in relationships:
            entity_connections[rel.source_id] = entity_connections.get(rel.source_id, 0) + 1
            entity_connections[rel.target_id] = entity_connections.get(rel.target_id, 0) + 1

        central_entities = sorted(entity_connections.items(), key=lambda x: x[1], reverse=True)[:10]

        high_risk = [e for e in entities if e.risk_score > 0.5]
        critical_paths: list[dict[str, object]] = []
        for entity in high_risk[:5]:
            chain = [entity.id]
            current = entity.id
            for _ in range(3):
                next_rels = adjacency.get(current, [])
                if next_rels:
                    best = max(next_rels, key=lambda r: r.confidence)
                    chain.append(best.target_id)
                    current = best.target_id
                else:
                    break
            if len(chain) > 1:
                critical_paths.append({"path": chain, "risk_score": entity.risk_score})

        type_counts: dict[str, int] = {}
        for e in entities:
            type_counts[e.entity_type] = type_counts.get(e.entity_type, 0) + 1

        processed = {
            "network_stats": stats,
            "central_entities": [
                {"id": eid, "connections": count}
                for eid, count in central_entities
            ],
            "critical_paths": critical_paths,
            "entity_types": type_counts,
            "total_entities": len(entities),
            "total_relationships": len(relationships),
        }

        return IntelligenceResult(
            source="network_analyzer",
            data_type="network_analysis",
            confidence=0.8,
            raw_data=processed,
            processed_data=processed,
            category="technical",
            severity="info",
            metadata={"entities": len(entities), "relationships": len(relationships)},
        )
