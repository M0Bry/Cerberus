"""
AI Engine — Main orchestrator for all AI operations.
"""

import structlog

from app.ai.models.model_router import model_router
from app.ai.prompts.system_prompt import (
    DEFENSE_RECOMMENDATION_PROMPT,
    EXPLAIN_DECISION_PROMPT,
    INTAKE_PROMPT,
    OSINT_ANALYSIS_PROMPT,
    RED_TEAM_PROMPT,
    REPORT_EXECUTIVE_PROMPT,
    RISK_ASSESSMENT_PROMPT,
    SCOPE_GENERATION_PROMPT,
    SYSTEM_PROMPT,
)

logger = structlog.get_logger()


class AIEngine:
    """
    Main AI orchestrator. Routes tasks to the appropriate model
    and prompt template.
    """

    async def intake_conversation(self, history: list[dict], context: str = "") -> str:
        system_content = SYSTEM_PROMPT + "\n\n" + INTAKE_PROMPT
        messages = [{"role": "system", "content": system_content}]
        if context:
            messages.append({"role": "system", "content": f"Context: {context}"})
        messages.extend(history[-20:])
        return await model_router.generate("conversation", messages)

    async def generate_scope(self, intake_summary: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{SCOPE_GENERATION_PROMPT}\n\n"
                    f"Intake Summary:\n{intake_summary}"
                ),
            },
        ]
        return await model_router.generate_json("scope_generation", messages)

    async def analyze_osint(self, findings: list[dict]) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{OSINT_ANALYSIS_PROMPT}\n\nFindings:\n{findings}"
                ),
            },
        ]
        return await model_router.generate("osint_analysis", messages)

    async def plan_attacks(self, intelligence: str, scope: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{RED_TEAM_PROMPT}\n\n"
                    f"Intelligence:\n{intelligence}\n\n"
                    f"Scope:\n{scope}"
                ),
            },
        ]
        return await model_router.generate_json("attack_planning", messages)

    async def assess_risk(self, vulnerabilities: list[dict], org_context: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{RISK_ASSESSMENT_PROMPT}\n\n"
                    f"Vulnerabilities:\n{vulnerabilities}\n\n"
                    f"Organization:\n{org_context}"
                ),
            },
        ]
        return await model_router.generate_json("risk_assessment", messages)

    async def generate_executive_summary(self, data: dict) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{REPORT_EXECUTIVE_PROMPT}\n\nData:\n{data}"},
        ]
        return await model_router.generate("report_generation", messages)

    async def explain_decision(self, finding: dict) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{EXPLAIN_DECISION_PROMPT}\n\nFinding:\n{finding}"},
        ]
        return await model_router.generate("explain_decision", messages)

    async def defense_recommendations(self, attack_patterns: list[dict]) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{DEFENSE_RECOMMENDATION_PROMPT}\n\n"
                    f"Attack Patterns:\n{attack_patterns}"
                ),
            },
        ]
        return await model_router.generate_json("defense_recommendation", messages)


ai_engine = AIEngine()
