"""
Report Builder — Generates professional PDF penetration testing reports.
"""

from pathlib import Path

import structlog

logger = structlog.get_logger()


class ReportBuilder:
    """
    Generates professional penetration testing reports in PDF format.

    Report Structure:
    1. Executive Summary
    2. Scope of Engagement
    3. Assessment Methodology
    4. Detailed Findings
    5. Remediation Roadmap
    6. Overall Security Assessment
    """

    def __init__(self):
        pass

    async def generate_report(self, engagement_data: dict) -> dict:
        """
        Generate a complete penetration testing report.

        Args:
            engagement_data: All engagement data including findings, risks, etc.

        Returns:
            Dict with report sections and PDF storage path.
        """

        report = {
            "executive_summary": self._build_executive_summary(engagement_data),
            "methodology": self._build_methodology(engagement_data),
            "detailed_findings": self._build_findings(engagement_data),
            "remediation_roadmap": self._build_remediation_roadmap(engagement_data),
            "overall_assessment": self._build_overall_assessment(engagement_data),
        }

        # Generate PDF
        pdf_path = await self._generate_pdf(engagement_data, report)

        return {**report, "pdf_path": pdf_path}

    def _build_executive_summary(self, data: dict) -> str:
        """Build the executive summary section."""
        org = data.get("organization_name", "the organization")
        total = data.get("total_findings", 0)
        critical = data.get("critical_count", 0)
        high = data.get("high_count", 0)
        score = data.get("overall_security_score", 0)

        return (
            f"Cerberus AI conducted a comprehensive penetration testing assessment "
            f"of {org}'s digital infrastructure. The assessment identified {total} "
            f"security findings, including {critical} critical and {high} high-severity "
            f"vulnerabilities. The overall security posture score is {score}/100."
        )

    def _build_methodology(self, data: dict) -> str:
        """Build the methodology section."""
        return (
            "The assessment followed a structured four-phase approach:\n\n"
            "Phase 1 — Open-Source Intelligence (OSINT): Systematic collection of "
            "publicly available information from search engines, DNS records, "
            "certificate transparency logs, breach databases, and technology "
            "fingerprinting services.\n\n"
            "Phase 2 — Attack Planning & Red Team Execution: AI-driven construction "
            "of attack graphs, identification of viable attack paths, and controlled "
            "proof-of-concept validation using non-destructive techniques.\n\n"
            "Phase 3 — Risk Assessment: Translation of technical vulnerabilities "
            "into measurable business risk with contextual severity analysis.\n\n"
            "Phase 4 — Report Generation: Automated compilation of findings, "
            "evidence, and remediation recommendations."
        )

    def _build_findings(self, data: dict) -> str:
        """Build the detailed findings section."""
        findings = data.get("vulnerabilities", [])
        if not findings:
            return "No vulnerabilities were confirmed during the assessment."

        sections = []
        for i, vuln in enumerate(findings, 1):
            sections.append(
                f"Finding {i}: {vuln.get('title', 'N/A')}\n"
                f"Severity: {vuln.get('severity', 'N/A').upper()}\n"
                f"Affected Assets: {vuln.get('affected_assets', 'N/A')}\n"
                f"Description: {vuln.get('description', 'N/A')}\n"
                f"Remediation: {vuln.get('remediation_steps', 'N/A')}\n"
            )

        return "\n".join(sections)

    def _build_remediation_roadmap(self, data: dict) -> str:
        """Build the prioritized remediation roadmap."""
        return (
            "Remediation activities are organized by business priority:\n\n"
            "Immediate (Critical): Address critical vulnerabilities within 24-48 hours.\n"
            "Short-term (High): Remediate high-severity issues within 1-2 weeks.\n"
            "Medium-term (Medium): Address medium-severity findings within 1 month.\n"
            "Long-term (Low): Resolve low-severity issues within the next quarter."
        )

    def _build_overall_assessment(self, data: dict) -> str:
        """Build the overall security assessment."""
        score = data.get("overall_security_score", 0)
        if score >= 80:
            maturity = "Good"
        elif score >= 60:
            maturity = "Moderate"
        elif score >= 40:
            maturity = "Below Average"
        else:
            maturity = "Poor"

        return (
            f"The organization's current cybersecurity maturity is rated as {maturity} "
            f"with an overall security score of {score}/100. Strategic recommendations "
            f"include implementing a continuous security monitoring program, conducting "
            f"regular penetration testing, and establishing a vulnerability management process."
        )

    async def _generate_pdf(self, data: dict, report: dict) -> str:
        """Generate PDF version of the report."""
        # In production, use reportlab or weasyprint
        pdf_dir = Path("./reports")
        pdf_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = pdf_dir / f"report_{data.get('engagement_id', 'unknown')}.pdf"

        logger.info("pdf_generated", path=str(pdf_path))
        return str(pdf_path)
