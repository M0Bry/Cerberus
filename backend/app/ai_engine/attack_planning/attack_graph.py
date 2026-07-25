"""
Attack Graph Builder — Constructs attack paths from OSINT intelligence.
"""

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class AttackGraphBuilder:
    """
    Builds an attack graph from collected OSINT data.

    Analyzes relationships between discovered assets to identify
    the most probable and impactful attack paths.
    """

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def build_attack_paths(
        self,
        findings: list[dict],
        knowledge_graph: dict,
        scope_context: str,
    ) -> list[dict]:
        """
        Analyze OSINT findings and generate prioritized attack paths.

        Args:
            findings: List of OSINT finding dicts.
            knowledge_graph: Nodes and edges from OSINT phase.
            scope_context: Engagement scope and constraints.

        Returns:
            List of attack path dicts with priorities and confidence scores.
        """

        # Prepare findings summary for AI
        findings_text = self._format_findings(findings)

        prompt = f"""Based on the following OSINT intelligence, identify the most probable
attack paths a real adversary could use to compromise the target organization.

Findings:
{findings_text}

Scope Context:
{scope_context}

For each attack path, provide:
1. name: Descriptive name
2. description: Detailed explanation
3. initial_entry_point: Where the attack begins
4. expected_impact: Potential damage
5. technical_feasibility: Score 0-1
6. business_impact: Score 0-1
7. confidence_score: Score 0-1
8. priority: 1 = highest
9. steps: List of sequential attack steps

Format as JSON array. Identify 3-5 most realistic attack paths."""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert penetration tester and red team operator. "
                            "Analyze intelligence and identify realistic attack paths."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=settings.OPENAI_MAX_TOKENS,
                temperature=0.3,
                response_format={"type": "json_object"},
            )

            import json
            result = json.loads(response.choices[0].message.content)
            return result.get("attack_paths", result.get("attack_paths", []))

        except Exception as e:
            logger.error("attack_graph_error", error=str(e))
            return []

    def _format_findings(self, findings: list[dict]) -> str:
        """Format findings into a readable summary."""
        lines = []
        for f in findings:
            category = f.get("category", "unknown").upper()
            title = f.get("title", "N/A")
            description = f.get("description", "N/A")
            lines.append(
                f"- [{category}] {title}: {description}"
            )
        return "\n".join(lines) if lines else "No findings available."
