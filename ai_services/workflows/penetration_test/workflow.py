"""
Penetration Test Workflow — Full pentest lifecycle.
"""
import structlog

logger = structlog.get_logger()

WORKFLOW_DEFINITION = {
    "name": "Full Penetration Test",
    "version": "1.0",
    "steps": [
        {"id": "intake", "agent": "intake_agent", "task": "collect_requirements"},
        {"id": "scope", "agent": "scope_agent", "task": "generate_scope"},
        {"id": "roe", "agent": "roe_agent", "task": "generate_roe"},
        {"id": "osint", "agent": "osint_agent", "task": "collect_intelligence"},
        {"id": "recon", "agent": "reconnaissance_agent", "task": "enumerate_assets"},
        {"id": "vuln_scan", "agent": "vulnerability_agent", "task": "assess"},
        {"id": "exploit", "agent": "exploit_agent", "task": "validate"},
        {"id": "risk", "agent": "risk_assessment_agent", "task": "assess"},
        {"id": "report", "agent": "report_agent", "task": "generate"},
    ],
}
