"""
Risk Analyzer — Translates technical vulnerabilities into business risk.
"""

import json

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class RiskAnalyzer:
    """
    Analyzes confirmed vulnerabilities and generates business risk assessments.
    """

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def assess_risks(
        self,
        vulnerabilities: list[dict],
        organization_context: str,
    ) -> list[dict]:
        """
        Generate risk assessments for confirmed vulnerabilities.

        Args:
            vulnerabilities: List of confirmed vulnerability dicts.
            organization_context: Organization profile and business context.

        Returns:
            List of risk assessment dicts.
        """

        vulns_text = json.dumps(vulnerabilities, indent=2)

        prompt = f"""Analyze the following confirmed vulnerabilities and generate
 business risk assessments for each.

Vulnerabilities:
{vulns_text}

Organization Context:
{organization_context}

For each vulnerability, provide:
1. risk_level: "low", "medium", "high", or "critical"
2. likelihood_of_exploitation: 0-1 score
3. complexity_required: "low", "medium", or "high"
4. privileges_obtainable: Description of access level
5. asset_sensitivity: 0-1 score
6. cumulative_risk_score: 0-1 weighted score
7. potential_consequences: Dict with confidentiality, integrity, availability impacts
8. affected_services: Which business services would be impacted
9. regulatory_implications: Compliance implications
10. remediation_priority: 1 = highest priority
11. estimated_remediation_effort: "hours", "days", "weeks", or "months"

Consider the organization's context when assessing business impact.
A SQL injection in a marketing site is different from the same vuln in a financial system.

Format as JSON array."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert risk analyst specializing in cybersecurity. "
                            "Translate technical vulnerabilities into measurable business risk."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=settings.OPENAI_MAX_TOKENS,
                temperature=0.3,
                response_format={"type": "json_object"},
            )

            result = json.loads(response.choices[0].message.content)
            return result.get("risk_assessments", result.get("assessments", []))

        except Exception as e:
            logger.error("risk_analysis_error", error=str(e))
            return []

    async def validate_findings(self, vulnerabilities: list[dict]) -> dict:
        """
        AI Decision Validation — Verify every finding has supporting evidence.

        Prevents AI hallucinations by requiring verifiable technical evidence.
        """

        vulns_text = json.dumps(vulnerabilities, indent=2)

        prompt = f"""Review the following vulnerabilities and verify each finding.

For each vulnerability:
- Verify that sufficient evidence exists
- Check for duplicates
- Check for contradictory conclusions
- Identify any unsupported assumptions

Vulnerabilities:
{vulns_text}

Return JSON with:
- validated: List of validated finding IDs
- downgraded: List of finding IDs that need manual review
- excluded: List of finding IDs that should be removed (insufficient evidence)
- duplicates: List of duplicate finding ID pairs"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a quality assurance reviewer for penetration testing reports. "
                            "Ensure every finding is supported by verifiable evidence."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
                temperature=0.2,
                response_format={"type": "json_object"},
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error("validation_error", error=str(e))
            return {"validated": [], "downgraded": [], "excluded": [], "duplicates": []}
