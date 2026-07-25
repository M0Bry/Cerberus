"""Report Tools — Report formatting, chart generation, PDF compilation."""

import structlog

logger = structlog.get_logger()


class ReportTools:
    """Tools for generating professional penetration testing reports."""

    async def format_findings(self, vulnerabilities: list[dict]) -> str:
        """Format vulnerabilities into report-ready HTML."""
        sections = []
        for i, vuln in enumerate(vulnerabilities, 1):
            sections.append(f"""
            <div class="finding">
                <h3>Finding {i}: {vuln.get('title', 'N/A')}</h3>
                <p><strong>Severity:</strong> {vuln.get('severity', 'N/A').upper()}</p>
                <p><strong>Description:</strong> {vuln.get('description', '')}</p>
                <p><strong>Remediation:</strong> {vuln.get('remediation_steps', '')}</p>
            </div>
            """)
        return "\n".join(sections)

    async def generate_remediation_roadmap(self, findings: list[dict]) -> str:
        """Generate a prioritized remediation roadmap."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 4),
        )
        roadmap = []
        for f in sorted_findings:
            roadmap.append(
                f"- [{f.get('severity', 'N/A').upper()}] "
                f"{f.get('title')}: {f.get('remediation_steps', 'N/A')}"
            )
        return "\n".join(roadmap)
