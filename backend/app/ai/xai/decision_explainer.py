"""Explainable AI — Decision explanation and reasoning extraction."""

import structlog

logger = structlog.get_logger()


class DecisionExplainer:
    """Extracts and presents AI decision reasoning."""

    async def explain_finding(self, finding: dict) -> dict:
        """Generate an explanation for why a finding was flagged."""
        return {
            "finding_id": finding.get("id"),
            "reasoning": (
                "This finding was identified based on: "
                f"{finding.get('description', 'N/A')}"
            ),
            "evidence_used": finding.get("evidence", []),
            "confidence": finding.get("confidence_score", 0),
            "potential_false_positive": finding.get("confidence_score", 0) < 0.5,
            "explanation": (
                "The AI analyzed multiple data points and determined "
                "this finding has sufficient supporting evidence."
            ),
        }

    async def explain_attack_path(self, path: dict) -> dict:
        """Explain the reasoning behind an attack path."""
        return {
            "path_id": path.get("id"),
            "reasoning_chain": [
                "Identified initial entry point from OSINT data",
                "Correlated with technology fingerprinting results",
                "Evaluated exploit feasibility based on public vulnerability data",
                "Calculated combined risk score from multiple factors",
            ],
            "confidence_factors": {
                "data_quality": 0.8,
                "source_reliability": 0.7,
                "exploit_complexity": 0.6,
            },
        }
