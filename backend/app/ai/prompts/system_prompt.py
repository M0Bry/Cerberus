"""
AI Prompt Templates — All prompts used by the Cerberus AI engine.
"""

SYSTEM_PROMPT = """You are Cerberus AI, an elite cybersecurity assistant. You guide clients through
penetration testing engagements with expertise, professionalism, and ethical rigor.

Core Principles:
- Non-destructive testing only
- Evidence-based findings
- Legal compliance always
- Adaptive questioning based on organization type
- Professional, clear communication
"""

INTAKE_PROMPT = """Begin the intake conversation. Ask one question at a time to understand:
1. Organization type and industry
2. Size and structure
3. Critical digital assets
4. Domains, IPs, applications to test
5. Systems to exclude
6. Testing period and constraints
7. Compliance requirements
8. Security priorities

Adapt your questions based on the organization's industry.
"""

SCOPE_GENERATION_PROMPT = (
    """Based on the intake conversation, generate a structured Scope of Engagement """
    """document.
Include: organization profile, business objectives, critical assets, authorized """
    """targets, out-of-scope items,
expected duration, security priorities, technical constraints, and compliance """
    """considerations.
Format as JSON.
"""
)

OSINT_ANALYSIS_PROMPT = """Analyze the following OSINT findings and identify:
1. Key infrastructure components
2. Technology stack details
3. Potential attack surface
4. Employee-related risks
5. Historical exposures
6. Credential leak risks
Provide a structured intelligence summary.
"""

RED_TEAM_PROMPT = """Based on collected intelligence, construct attack paths:
1. Identify viable entry points
2. Evaluate exploit probability (0-1)
3. Estimate business impact (0-1)
4. Chain low-risk vulns into high-impact attacks
5. Prioritize by feasibility × impact
Format as prioritized attack path array.
"""

RISK_ASSESSMENT_PROMPT = (
    """Translate the following technical vulnerabilities into business risk """
    """assessments.
For each: risk_level, likelihood, impact, business consequences, affected """
    """services, remediation priority.
Consider the organization context when assessing impact.
"""
)

REPORT_EXECUTIVE_PROMPT = """Generate an executive summary for a penetration testing report.
Write in non-technical language for senior management.
Include: objectives, methodology overview, key findings, overall security """
"""posture, top recommendations.
"""

EXPLAIN_DECISION_PROMPT = """Explain the reasoning behind the following security finding.
Provide: chain-of-thought, evidence used, confidence level, and potential """
"""false positive indicators.
"""

DEFENSE_RECOMMENDATION_PROMPT = (
    """Based on the following attack patterns, generate defensive recommendations:
1. Virtual patch rules
2. WAF configuration updates
3. Network segmentation advice
4. Monitoring rule suggestions
"""
)
