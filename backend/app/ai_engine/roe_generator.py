"""
Rules of Engagement Generator — Auto-generates legal RoE documents.
"""

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class RoEGenerator:
    """Generates Rules of Engagement documents using AI."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def generate(self, engagement, scope) -> dict:
        """
        Generate a complete Rules of Engagement document.

        Returns:
            Dict with 'html', 'text', and individual clause fields.
        """

        # Build clauses directly — the scope_context variable is no longer needed
        clauses = {
            "authorization": self._generate_authorization_clause(engagement, scope),
            "methodology": self._generate_methodology_clause(scope),
            "prohibited_actions": self._generate_prohibited_actions_clause(),
            "client_obligations": self._generate_client_obligations_clause(),
            "liability": self._generate_liability_clause(),
            "confidentiality": self._generate_confidentiality_clause(),
        }

        html = self._build_html_document(engagement, scope, clauses)
        text = self._build_text_document(engagement, scope, clauses)

        return {
            "html": html,
            "text": text,
            **clauses,
        }

    def _generate_authorization_clause(self, engagement, scope) -> str:
        return (
            f"The Client ({engagement.organization_name}) hereby explicitly authorizes "
            f"Cerberus AI to perform security assessment activities exclusively against "
            f"the assets listed within the approved Scope of Engagement "
            f"(ID: {engagement.engagement_number}). "
            f"This authorization is limited to the testing period and constraints defined herein."
        )

    def _generate_methodology_clause(self, scope) -> str:
        phases = []
        if scope.include_osint:
            phases.append("Open-Source Intelligence (OSINT) collection")
        if scope.include_red_team:
            phases.append("Red Team simulation and controlled vulnerability validation")
        if scope.include_risk_assessment:
            phases.append("Risk assessment and business impact analysis")
        if scope.include_report_generation:
            phases.append("Automated report generation")

        return (
            f"Cerberus AI will employ the following non-destructive techniques: "
            f"Passive reconnaissance, {', '.join(phases)}. "
            f"All activities are fully documented and immediately reversible."
        )

    def _generate_prohibited_actions_clause(self) -> str:
        return (
            "Cerberus AI explicitly prohibits: deletion of production data, "
            "modification of operational systems, denial-of-service attacks, "
            "permanent infrastructure compromise, retention of sensitive client "
            "information after engagement completion, and testing of systems "
            "marked as out-of-scope."
        )

    def _generate_client_obligations_clause(self) -> str:
        return (
            "The Client agrees to: provide accurate information regarding infrastructure, "
            "authorize all assets listed in the scope, notify relevant stakeholders, "
            "cooperate during clarification requests, and maintain confidentiality "
            "regarding discovered vulnerabilities until remediation is complete."
        )

    def _generate_liability_clause(self) -> str:
        return (
            "Cerberus AI operates as a non-destructive security assessment platform. "
            "All activities are performed within the authorized scope using controlled "
            "proof-of-concept techniques. Neither party shall be liable for indirect, "
            "consequential, or incidental damages arising from the assessment."
        )

    def _generate_confidentiality_clause(self) -> str:
        return (
            "All information collected during the engagement, including findings, "
            "evidence, reports, and organizational details, shall be treated as "
            "confidential. Cerberus AI will not retain sensitive client data after "
            "engagement completion. All data is encrypted both in transit and at rest."
        )

    def _build_html_document(self, engagement, scope, clauses) -> str:
        return f"""
<div class="roe-document">
    <h1>Rules of Engagement</h1>
    <p><strong>Engagement ID:</strong> {engagement.engagement_number}</p>
    <p><strong>Client:</strong> {engagement.organization_name}</p>
    <p><strong>Date:</strong> {engagement.created_at.strftime('%Y-%m-%d')}</p>

    <h2>1. Authorization</h2>
    <p>{clauses['authorization']}</p>

    <h2>2. Methodology</h2>
    <p>{clauses['methodology']}</p>

    <h2>3. Prohibited Actions</h2>
    <p>{clauses['prohibited_actions']}</p>

    <h2>4. Client Obligations</h2>
    <p>{clauses['client_obligations']}</p>

    <h2>5. Liability</h2>
    <p>{clauses['liability']}</p>

    <h2>6. Confidentiality</h2>
    <p>{clauses['confidentiality']}</p>
</div>
"""

    def _build_text_document(self, engagement, scope, clauses) -> str:
        return f"""RULES OF ENGAGEMENT
Engagement ID: {engagement.engagement_number}
Client: {engagement.organization_name}
Date: {engagement.created_at.strftime('%Y-%m-%d')}

1. AUTHORIZATION
{clauses['authorization']}

2. METHODOLOGY
{clauses['methodology']}

3. PROHIBITED ACTIONS
{clauses['prohibited_actions']}

4. CLIENT OBLIGATIONS
{clauses['client_obligations']}

5. LIABILITY
{clauses['liability']}

6. CONFIDENTIALITY
{clauses['confidentiality']}
"""
