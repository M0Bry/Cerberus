"""
Rules of Engagement Generator — Auto-generates legal RoE documents.
"""

from html import escape as _esc

import structlog
from openai import AsyncOpenAI

from app.core.config import settings

logger = structlog.get_logger()


class RoEGenerator:
    """Generates Rules of Engagement documents using AI."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

    async def generate(
        self, engagement, scope, assets: list | None = None
    ) -> dict:
        """
        Generate a complete Rules of Engagement document.
        ``assets`` = the scope's asset rows (authorized + excluded targets)
        listed in the document.

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

        html = self._build_html_document(engagement, scope, clauses, assets)
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

    def build_html(
        self,
        engagement,
        scope,
        clauses: dict,
        assets: list | None = None,
        signed_name: str | None = None,
        signed_at=None,
        signature_hash: str | None = None,
    ) -> str:
        """Render the complete document: Part A (Scope of Engagement) +
        Part B (Rules of Engagement) + the digital authorization block.

        ``assets`` is an explicit list of asset rows (avoids lazy
        relationship loads in async contexts).
        """
        assets = assets or []
        in_scope = [a for a in assets if not getattr(a, "is_excluded", False)]
        excluded = [a for a in assets if getattr(a, "is_excluded", False)]

        in_scope_html = (
            "<ul>" + "".join(f"<li><code>{_esc(a.value)}</code></li>" for a in in_scope) + "</ul>"
            if in_scope
            else '<p class="doc-muted">As described in the engagement conversation.</p>'
        )
        excluded_html = (
            "<ul>" + "".join(f"<li><code>{_esc(a.value)}</code></li>" for a in excluded) + "</ul>"
            if excluded
            else '<p class="doc-muted">None declared.</p>'
        )

        # Everything interpolated below that came from user input is HTML-
        # escaped: this fragment is rendered with dangerouslySetInnerHTML.
        org_name = _esc(engagement.organization_name or "—")
        eng_number = _esc(engagement.engagement_number)
        scope_summary = _esc(scope.summary or "")
        scope_objective = _esc(scope.testing_objective or "")
        esc_clauses = {k: _esc(v or "") for k, v in clauses.items()}
        esc_signed = _esc(signed_name) if signed_name else None

        if signed_name:
            signed_dt = signed_at.strftime("%Y-%m-%d %H:%M UTC") if signed_at else "—"
            signature_html = f"""
    <div class="doc-signature signed">
        <h2>Digital Authorization</h2>
        <p class="signed-name">{esc_signed}</p>
        <p class="doc-muted">Signed {signed_dt} · Cryptographic verification hash:
        <code>{signature_hash or "—"}</code></p>
        <p>This engagement is <strong>authorized and active</strong>. The signed
        agreement is permanently linked to the engagement record.</p>
    </div>"""
        else:
            signature_html = """
    <div class="doc-signature">
        <h2>Digital Authorization</h2>
        <p>To authorize this engagement, the client representative must type
        their full legal name in the signature field below. Copy-paste is
        disabled — the signature must be entered deliberately. It is then
        cryptographically sealed and permanently linked to this engagement
        record, which serves as the legal and technical foundation for all
        subsequent assessment activity.</p>
    </div>"""

        return f"""
<div class="roe-document">
    <div class="doc-header">
        <h1>Scope of Engagement &amp; Rules of Engagement</h1>
        <p class="doc-meta">
            <span><strong>Engagement ID:</strong> {eng_number}</span>
            <span><strong>Client:</strong> {org_name}</span>
            <span><strong>Date:</strong> {engagement.created_at.strftime('%Y-%m-%d')}</span>
            <span><strong>Status:</strong> {("SIGNED — AUTHORIZED" if signed_name else "PENDING SIGNATURE")}</span>
        </p>
    </div>

    <h2>Part A — Scope of Engagement</h2>

    <h3>A.1 Engagement Overview</h3>
    <p>{scope_summary}</p>
    <p><strong>Objective:</strong> {scope_objective}</p>
    <p><strong>Testing nature:</strong> Non-destructive, fully documented,
    immediately reversible. Proof-of-concept level only.</p>

    <h3>A.2 Authorized Testing Targets</h3>
    {in_scope_html}

    <h3>A.3 Excluded Systems (Strictly Out of Scope)</h3>
    {excluded_html}

    <h3>A.4 Assessment Methodology &amp; Phases</h3>
    <p>{esc_clauses['methodology']}</p>

    <h3>A.5 Operational Constraints</h3>
    <p>Maximum impact: proof-of-concept only — no destructive actions, no data
    exfiltration, no service disruption. Testing is limited to the authorized
    targets and the agreed operational windows.</p>

    <h2>Part B — Rules of Engagement</h2>

    <h3>1. Authorization</h3>
    <p>{esc_clauses['authorization']}</p>

    <h3>2. Methodology</h3>
    <p>{esc_clauses['methodology']}</p>

    <h3>3. Prohibited Actions</h3>
    <p>{esc_clauses['prohibited_actions']}</p>

    <h3>4. Client Obligations</h3>
    <p>{esc_clauses['client_obligations']}</p>

    <h3>5. Liability</h3>
    <p>{esc_clauses['liability']}</p>

    <h3>6. Confidentiality</h3>
    <p>{esc_clauses['confidentiality']}</p>
    {signature_html}
</div>
"""

    def _build_html_document(
        self, engagement, scope, clauses, assets: list | None = None
    ) -> str:
        return self.build_html(engagement, scope, clauses, assets=assets)

    def _build_text_document(self, engagement, scope, clauses) -> str:
        # Plain-text mirror of the document (no HTML, so no escaping).
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
