"""Hallucination Guard — Fact-checks AI outputs against evidence."""

import structlog

logger = structlog.get_logger()


class HallucinationGuard:
    """Validates AI-generated findings against verifiable evidence."""

    async def validate_finding(self, finding: dict) -> dict:
        """Validate that a finding has sufficient supporting evidence."""
        evidence_score = 0.0
        issues = []

        if not finding.get("description"):
            issues.append("Missing description")
        if not finding.get("evidence") and not finding.get("proof_of_concept"):
            issues.append("No supporting evidence provided")
            evidence_score -= 0.5
        else:
            evidence_score += 0.5

        if finding.get("confidence_score", 0) < 0.3:
            issues.append("Very low confidence score")

        is_valid = len(issues) == 0 or evidence_score > 0

        recommendation = (
            "include" if is_valid
            else "exclude" if not finding.get("evidence")
            else "downgrade"
        )

        return {
            "is_valid": is_valid,
            "evidence_score": max(0, min(1, evidence_score + 0.5)),
            "issues": issues,
            "recommendation": recommendation,
        }

    async def validate_batch(self, findings: list[dict]) -> dict:
        validated, excluded, downgraded = [], [], []
        for f in findings:
            result = await self.validate_finding(f)
            if result["recommendation"] == "include":
                validated.append(f)
            elif result["recommendation"] == "exclude":
                excluded.append(f)
            else:
                downgraded.append(f)
        return {"validated": validated, "excluded": excluded, "downgraded": downgraded}
