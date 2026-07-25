"""
OSINT Engine — The brain of the intelligence system.

Orchestrates the complete intelligence cycle:
1. Collection — Multi-source parallel data gathering
2. Processing — Normalization, entity extraction, relationship building
3. Analysis — ACH, link analysis, timeline analysis, risk assessment
4. Production — Report generation with evidence and recommendations
"""

import asyncio
import uuid
from datetime import datetime, timezone

import structlog

from osint_framework.core import (
    Entity,
    IntelligenceReport,
    IntelligenceResult,
    Relationship,
)
from osint_framework.plugins.plugin_manager import PluginManager

logger = structlog.get_logger()


class OSINTEngine:
    """
    Main OSINT Engine — Orchestrates the complete intelligence cycle.
    """

    def __init__(self, config: dict[str, object] | None = None):
        self.config = config or {}
        self.plugin_manager: PluginManager | None = None
        self.results_cache: dict[str, object] = {}
        self.entities: list[Entity] = []
        self.relationships: list[Relationship] = []
        self.session = None
        self._initialized = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        logger.info("osint_engine_initializing")
        self.plugin_manager = PluginManager(self)
        await self.plugin_manager.load_plugins()
        self._initialized = True
        logger.info("osint_engine_initialized", plugins=len(self.plugin_manager.plugins))

    async def cleanup(self) -> None:
        if self.session:
            await self.session.close()
        self._initialized = False
        logger.info("osint_engine_cleanup")

    # ─── Intelligence Cycle ───────────────────────────────────

    async def run_intelligence_cycle(
        self,
        target: str,
        modules: list[str] | None = None,
        engagement_id: str | None = None,
    ) -> IntelligenceReport:
        if not self._initialized:
            await self.initialize()

        target_type = self._classify_target(target)
        logger.info(
            "intelligence_cycle_started",
            target=target,
            type=target_type,
            modules=modules,
        )

        raw_results = await self._collect(target, modules)
        processed = self._process(raw_results)
        analysis = self._analyze(processed)
        report = self._produce_report(target, target_type, analysis, raw_results)

        logger.info(
            "intelligence_cycle_completed",
            target=target,
            findings=len(raw_results),
            entities=len(self.entities),
            relationships=len(self.relationships),
        )
        return report

    # ─── Phase 1: Collection ──────────────────────────────────

    async def _collect(
        self, target: str, modules: list[str] | None = None
    ) -> list[IntelligenceResult]:
        module_plugins = {
            "socmint": ["username_enum", "social_scanner", "image_analysis"],
            "cybint": ["domain_intel", "github_scan", "shodan_search"],
            "darkweb": ["tor_scrape", "telegram_monitor"],
        }

        plugins_to_run: list[str] = []
        if modules is None:
            for plugin_list in module_plugins.values():
                plugins_to_run.extend(plugin_list)
        else:
            for mod in modules:
                plugins_to_run.extend(module_plugins.get(mod, []))

        assert self.plugin_manager is not None, "PluginManager not initialised"

        tasks = []
        for plugin_name in plugins_to_run:
            if plugin_name in self.plugin_manager.plugins:
                tasks.append(self._execute_plugin_safe(plugin_name, target))

        logger.info("collection_started", plugins=len(tasks))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results: list[IntelligenceResult] = []
        for r in results:
            if isinstance(r, IntelligenceResult):
                valid_results.append(r)
            elif isinstance(r, Exception):
                logger.error("plugin_execution_error", error=str(r))

        logger.info("collection_completed", results=len(valid_results))
        return valid_results

    async def _execute_plugin_safe(
        self, plugin_name: str, target: str
    ) -> IntelligenceResult | None:
        assert self.plugin_manager is not None, "PluginManager not initialised"
        try:
            return await self.plugin_manager.execute(plugin_name, target)
        except Exception as e:
            logger.error("plugin_error", plugin=plugin_name, error=str(e))
            return None

    # ─── Phase 2: Processing ──────────────────────────────────

    def _process(
        self, raw_results: list[IntelligenceResult]
    ) -> dict[str, object]:
        entities: list[Entity] = []
        relationships: list[Relationship] = []
        risk_indicators: list[dict[str, object]] = []
        findings_by_category: dict[str, list[IntelligenceResult]] = {}

        for result in raw_results:
            if result is None:
                continue

            ents = self._extract_entities(result)
            entities.extend(ents)
            self.entities.extend(ents)

            rels = self._build_relationships(result, ents)
            relationships.extend(rels)
            self.relationships.extend(rels)

            category = result.category
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(result)

            if result.confidence > 0.7:
                risk_indicators.append({
                    "source": result.source,
                    "confidence": result.confidence,
                    "data_type": result.data_type,
                    "severity": result.severity,
                })

        logger.info(
            "processing_completed",
            entities=len(entities),
            relationships=len(relationships),
            risk_indicators=len(risk_indicators),
        )
        return {
            "entities": entities,
            "relationships": relationships,
            "timeline": [],
            "risk_indicators": risk_indicators,
            "findings_by_category": findings_by_category,
        }

    def _extract_entities(self, result: IntelligenceResult) -> list[Entity]:
        entities: list[Entity] = []
        data = result.processed_data
        if not isinstance(data, dict):
            return entities

        for email in data.get("emails", []):
            entities.append(Entity(
                id=f"email:{email}",
                entity_type="email",
                label=email,
                source=result.source,
                risk_score=0.6 if result.category == "credential" else 0.3,
            ))
        for domain in data.get("domains", []):
            entities.append(Entity(
                id=f"domain:{domain}",
                entity_type="domain",
                label=domain,
                source=result.source,
                risk_score=0.2,
            ))
        for subdomain in data.get("subdomains", []):
            entities.append(Entity(
                id=f"subdomain:{subdomain}",
                entity_type="subdomain",
                label=subdomain,
                source=result.source,
                risk_score=0.1,
            ))
        for tech in data.get("technologies", []):
            entities.append(Entity(
                id=f"tech:{tech}",
                entity_type="technology",
                label=tech,
                source=result.source,
                risk_score=0.1,
            ))
        for profile in data.get("profiles", []):
            if isinstance(profile, dict) and profile.get("exists"):
                platform = profile.get("platform", "unknown")
                username = profile.get("username", "")
                entities.append(Entity(
                    id=f"profile:{platform}:{username}",
                    entity_type="username",
                    label=f"{platform}: {username}",
                    properties=profile,
                    source=result.source,
                    risk_score=0.4,
                ))
        for ip in data.get("ips", []):
            entities.append(Entity(
                id=f"ip:{ip}",
                entity_type="ip",
                label=ip,
                source=result.source,
                risk_score=0.3,
            ))
        return entities

    def _build_relationships(
        self, result: IntelligenceResult, entities: list[Entity]
    ) -> list[Relationship]:
        relationships: list[Relationship] = []
        data = result.processed_data
        if not isinstance(data, dict):
            return relationships

        domain = data.get("domain")
        if domain:
            for sub in data.get("subdomains", []):
                relationships.append(Relationship(
                    source_id=f"domain:{domain}",
                    target_id=f"subdomain:{sub}",
                    relationship_type="has_subdomain",
                    confidence=0.9,
                    evidence="DNS/certificate enumeration",
                ))
            for tech in data.get("technologies", []):
                relationships.append(Relationship(
                    source_id=f"domain:{domain}",
                    target_id=f"tech:{tech}",
                    relationship_type="uses",
                    confidence=0.8,
                    evidence="HTTP header/content analysis",
                ))

        for profile in data.get("profiles", []):
            if isinstance(profile, dict) and profile.get("exists"):
                relationships.append(Relationship(
                    source_id=f"domain:{domain or 'unknown'}",
                    target_id=(
                        f"profile:{profile.get('platform', '')}:"
                        f"{profile.get('username', '')}"
                    ),
                    relationship_type="associated_with",
                    confidence=0.5,
                    evidence=(
                        f"Username enumeration on "
                        f"{profile.get('platform', '')}"
                    ),
                ))
        return relationships

    # ─── Phase 3: Analysis ────────────────────────────────────

    def _analyze(self, processed: dict[str, object]) -> dict[str, object]:
        critical_paths = self._find_critical_paths()
        risk_assessment = self._assess_overall_risk(processed)
        tech_profile = self._build_technology_profile(processed)

        return {
            "critical_paths": critical_paths,
            "risk_assessment": risk_assessment,
            "technology_profile": tech_profile,
            "entity_count": len(processed["entities"]),       # type: ignore[arg-type]
            "relationship_count": len(processed["relationships"]),  # type: ignore[arg-type]
            "risk_indicators": processed["risk_indicators"],
        }

    def _find_critical_paths(self) -> list[dict[str, object]]:
        adjacency: dict[str, list[Relationship]] = {}
        for rel in self.relationships:
            adjacency.setdefault(rel.source_id, []).append(rel)

        high_risk = [e for e in self.entities if e.risk_score > 0.5]
        paths: list[dict[str, object]] = []
        for entity in high_risk[:5]:
            chain = [entity.id]
            current = entity.id
            for _ in range(3):
                next_rels = adjacency.get(current, [])
                if next_rels:
                    next_rel = max(next_rels, key=lambda r: r.confidence)
                    chain.append(next_rel.target_id)
                    current = next_rel.target_id
                else:
                    break
            if len(chain) > 1:
                paths.append({
                    "path": chain,
                    "risk_score": entity.risk_score,
                    "length": len(chain),
                })

        paths.sort(key=lambda p: float(p["risk_score"]), reverse=True)  # type: ignore[arg-type]
        return paths

    def _assess_overall_risk(
        self, processed: dict[str, object]
    ) -> dict[str, object]:
        risk_indicators = processed.get("risk_indicators", [])
        if not isinstance(risk_indicators, list) or not risk_indicators:
            return {"overall_score": 0.0, "level": "low", "indicators": 0}

        avg_confidence = sum(
            r["confidence"] for r in risk_indicators  # type: ignore[misc]
        ) / len(risk_indicators)
        high_count = sum(
            1 for r in risk_indicators
            if r.get("severity") in ("critical", "high")
        )

        overall_score = min(1.0, avg_confidence * (1 + high_count * 0.2))

        if overall_score > 0.8:
            level = "critical"
        elif overall_score > 0.6:
            level = "high"
        elif overall_score > 0.3:
            level = "medium"
        else:
            level = "low"

        return {
            "overall_score": round(overall_score, 2),
            "level": level,
            "indicators": len(risk_indicators),
            "high_severity_count": high_count,
        }

    def _build_technology_profile(
        self, processed: dict[str, object]
    ) -> dict[str, object]:
        techs = set()
        for entity in self.entities:
            if entity.entity_type == "technology":
                techs.add(entity.label)
        return {
            "technologies": sorted(techs),
            "count": len(techs),
        }

    # ─── Phase 4: Production ──────────────────────────────────

    def _produce_report(
        self,
        target: str,
        target_type: str,
        analysis: dict[str, object],
        raw_results: list[IntelligenceResult],
    ) -> IntelligenceReport:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')  # noqa: UP017
        report_id = f"INT-{timestamp}-{uuid.uuid4().hex[:6]}"

        risk_assessment = analysis.get("risk_assessment", {})
        if not isinstance(risk_assessment, dict):
            risk_assessment = {}

        high_count = risk_assessment.get("high_severity_count", 0)
        summary_parts = [
            f"Intelligence gathering completed for target: {target} ({target_type}).",
            f"Collected {len(raw_results)} intelligence results from multiple sources.",
            (
                f"Identified {len(self.entities)} entities and "
                f"{len(self.relationships)} relationships."
            ),
            (
                f"Overall risk assessment: "
                f"{risk_assessment.get('level', 'unknown').upper()}."
            ),
        ]
        if high_count > 0:
            summary_parts.append(
                f"⚠️ {high_count} high-severity risk indicators detected."
            )

        risk_level = risk_assessment.get("level", "low")
        classification = (
            "CONFIDENTIAL" if risk_level in ("critical", "high") else "INTERNAL"
        )

        recommendations: list[str] = []
        if risk_level in ("critical", "high"):
            recommendations.append(
                "Immediate review of exposed credentials and sensitive data required."
            )
        tech_profile = analysis.get("technology_profile", {})
        if isinstance(tech_profile, dict) and tech_profile.get("count", 0) > 0:
            recommendations.append(
                "Review technology stack for known vulnerabilities and outdated components."
            )
        if any(e.entity_type == "email" for e in self.entities):
            recommendations.append(
                "Monitor exposed email addresses for phishing and credential stuffing attacks."
            )
        recommendations.append("Implement continuous monitoring for newly exposed assets.")
        recommendations.append(
            "Conduct regular penetration testing to validate security posture."
        )

        sources = list(set(r.source for r in raw_results if r))

        findings_by_category: dict[str, list[dict[str, object]]] = {}
        for result in raw_results:
            if result:
                cat = result.category
                if cat not in findings_by_category:
                    findings_by_category[cat] = []
                findings_by_category[cat].append(result.to_dict())

        detailed_findings = {
            "by_category": findings_by_category,
            "entities": [e.__dict__ for e in self.entities],
            "relationships": [r.__dict__ for r in self.relationships],
            "technology_profile": tech_profile,
            "critical_paths": analysis.get("critical_paths", []),
        }

        return IntelligenceReport(
            report_id=report_id,
            target=target,
            target_type=target_type,
            classification=classification,
            executive_summary=" ".join(summary_parts),
            detailed_findings=detailed_findings,
            entities=self.entities,
            relationships=self.relationships,
            risk_assessment=risk_assessment,
            confidence_level=risk_assessment.get("overall_score", 0.0),
            recommendations=recommendations,
            sources=sources,
        )

    @staticmethod
    def _classify_target(target: str) -> str:
        if "@" in target:
            return "email"
        elif target.startswith("http://") or target.startswith("https://"):
            return "url"
        elif "." in target and " " not in target:
            return "domain"
        else:
            return "username"
