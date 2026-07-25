"""
OSINT Reporting — Generates structured intelligence reports.
"""

import json

import structlog

from osint_framework.core import IntelligenceReport

logger = structlog.get_logger()


class OSINTReporter:
    """Generates structured intelligence reports from OSINT findings."""

    def generate_json_report(self, report: IntelligenceReport) -> str:
        return json.dumps({
            "report_id": report.report_id,
            "target": report.target,
            "target_type": report.target_type,
            "classification": report.classification,
            "executive_summary": report.executive_summary,
            "risk_assessment": report.risk_assessment,
            "confidence_level": report.confidence_level,
            "entity_count": len(report.entities),
            "relationship_count": len(report.relationships),
            "recommendations": report.recommendations,
            "sources": report.sources,
            "detailed_findings": report.detailed_findings,
            "timestamp": report.timestamp,
        }, indent=2, default=str)

    def generate_html_report(self, report: IntelligenceReport) -> str:
        risk_color = {
            "critical": "#ff3b5c", "high": "#ff8c00",
            "medium": "#ffd700", "low": "#00ff88",
        }.get(report.risk_assessment.get("level", "low"), "#00d4ff")

        findings_html = ""
        for category, items in report.detailed_findings.get("by_category", {}).items():
            findings_html += f"<h3>{category.upper()}</h3><ul>"
            for item in items[:10]:
                if isinstance(item, dict):
                    findings_html += (
                        f"<li><strong>{item.get('data_type', 'N/A')}</strong>: "
                        f"{item.get('source', 'N/A')} "
                        f"(Confidence: {item.get('confidence', 0):.0%})</li>"
                    )
            findings_html += "</ul>"

        return (
            "<!DOCTYPE html>"
            "<html><head><meta charset=\"UTF-8\"><style>"
            "body { font-family: 'Inter', Arial, sans-serif; "
            "background: #0a0a1a; color: #e0e0e0; padding: 40px; }"
            ".container { max-width: 900px; margin: 0 auto; "
            "background: #1a1a2e; border-radius: 12px; padding: 40px; "
            "border: 1px solid rgba(0,212,255,0.2); }"
            "h1 { color: #00d4ff; border-bottom: 3px solid #00d4ff; "
            "padding-bottom: 10px; }"
            "h2 { color: #0099cc; border-bottom: 1px solid #333; "
            "padding-bottom: 8px; }"
            ".risk-badge { display: inline-block; padding: 4px 12px; "
            "border-radius: 20px; color: white; font-weight: bold; "
            f"background: {risk_color}; }}"
            ".stat-grid { display: grid; grid-template-columns: "
            "repeat(4, 1fr); gap: 16px; margin: 20px 0; }"
            ".stat { background: #0d1117; padding: 16px; "
            "border-radius: 8px; text-align: center; "
            "border-left: 4px solid #00d4ff; }"
            ".stat-value { font-size: 28px; font-weight: bold; "
            "color: #00d4ff; }"
            ".footer { margin-top: 40px; "
            "border-top: 2px solid #00d4ff; padding-top: 16px; "
            "font-size: 11px; color: #666; text-align: center; }"
            "</style></head><body><div class=\"container\">"
            "<h1>🛡️ OSINT Intelligence Report</h1>"
            f"<p><strong>Report ID:</strong> {report.report_id}</p>"
            f"<p><strong>Target:</strong> {report.target} "
            f"({report.target_type})</p>"
            f"<p><strong>Classification:</strong> "
            f"{report.classification}</p>"
            "<p><strong>Risk Level:</strong> "
            "<span class=\"risk-badge\">"
            f"{report.risk_assessment.get('level', 'N/A').upper()}"
            "</span></p>"
            "<h2>Executive Summary</h2>"
            f"<p>{report.executive_summary}</p>"
            "<div class=\"stat-grid\">"
            "<div class=\"stat\"><div class=\"stat-value\">"
            f"{len(report.entities)}</div><div>Entities</div></div>"
            "<div class=\"stat\"><div class=\"stat-value\">"
            f"{len(report.relationships)}</div>"
            "<div>Relationships</div></div>"
            "<div class=\"stat\"><div class=\"stat-value\">"
            f"{report.confidence_level:.0%}</div>"
            "<div>Confidence</div></div>"
            "<div class=\"stat\"><div class=\"stat-value\">"
            f"{len(report.sources)}</div><div>Sources</div></div>"
            "</div>"
            "<h2>Findings by Category</h2>"
            f"{findings_html}"
            "<h2>Recommendations</h2><ol>"
            + "".join(f"<li>{r}</li>" for r in report.recommendations) +
            "</ol>"
            "<h2>Sources</h2><ul>"
            + "".join(f"<li>{s}</li>" for s in report.sources) +
            "</ul>"
            "<div class=\"footer\">"
            "<p>Cerberus AI — OSINT Intelligence Report — Generated "
            f"{report.timestamp}</p>"
            "<p>CONFIDENTIAL — For authorized recipients only</p>"
            "</div></div></body></html>"
        )

    def generate_summary(self, report: IntelligenceReport) -> dict[str, object]:
        by_category = report.detailed_findings.get("by_category", {})
        return {
            "report_id": report.report_id,
            "target": report.target,
            "total_findings": sum(
                len(items) for items in by_category.values()
            ),
            "entities_discovered": len(report.entities),
            "relationships_found": len(report.relationships),
            "risk_level": report.risk_assessment.get("level", "unknown"),
            "risk_score": report.risk_assessment.get("overall_score", 0.0),
            "confidence_level": report.confidence_level,
            "recommendations_count": len(report.recommendations),
            "sources_count": len(report.sources),
            "categories": {
                cat: len(items) for cat, items in by_category.items()
            },
        }
