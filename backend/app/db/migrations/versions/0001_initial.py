"""Initial migration — Create all 21 tables from SQLAlchemy models.

Revision ID: 0001
Revises: None
Create Date: 2026-07-11

Tables: users, otp_verifications, user_sessions, engagements,
        scopes_of_engagement, scope_assets, rules_of_engagement,
        digital_signatures, uploaded_documents, chat_sessions,
        chat_messages, osint_findings, knowledge_graph_nodes,
        knowledge_graph_edges, attack_paths, attack_path_steps,
        vulnerabilities, vulnerability_evidence, risk_assessments,
        reports, audit_logs, immutable_logs, ip_logs, security_alerts,
        incidents, blocked_ips, system_metrics, notifications,
        verification_codes
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ─── Enum Types ──────────────────────────────────────────
    userstatus = sa.Enum("pending_verification", "verified", "suspended", "deleted", name="userstatus")  # noqa: E501
    userrole = sa.Enum("user", "admin", "super_admin", name="userrole")  # noqa: E501
    engagementstatus = sa.Enum(  # noqa: E501
        "draft", "scope_defined", "rules_generated", "authorized", "initializing",  # noqa: E501
        "osint_in_progress", "osint_complete", "attack_planning", "attack_planning_complete",  # noqa: E501
        "red_team_in_progress", "red_team_complete", "risk_assessment",  # noqa: E501
        "risk_assessment_complete", "report_generating", "completed", "cancelled",  # noqa: E501
        name="engagementstatus"  # noqa: E501
    )
    sessionstatus = sa.Enum("intake", "scope_generation", "scope_confirmed", "in_progress", "completed", name="sessionstatus")  # noqa: E501
    findingcategory = sa.Enum("technical", "credential", "employee", "technology", "historical_web", name="findingcategory")  # noqa: E501
    attackpathstatus = sa.Enum("identified", "approved", "in_progress", "validated", "failed", "skipped", name="attackpathstatus")  # noqa: E501
    severitylevel = sa.Enum("low", "medium", "high", "critical", name="severitylevel")  # noqa: E501
    vulnerabilitystatus = sa.Enum("confirmed", "false_positive", "remediating", "remediated", "accepted_risk", name="vulnerabilitystatus")  # noqa: E501
    risklevel = sa.Enum("low", "medium", "high", "critical", name="risklevel")  # noqa: E501
    reportstatus = sa.Enum("generating", "generated", "signed", "delivered", name="reportstatus")  # noqa: E501
    auditaction = sa.Enum(  # noqa: E501
        "user_registered", "user_verified", "user_login", "user_logout", "user_login_failed",  # noqa: E501
        "password_changed", "engagement_created", "scope_defined", "rules_generated",  # noqa: E501
        "document_signed", "document_uploaded", "assessment_started", "phase_completed",  # noqa: E501
        "assessment_completed", "report_generated", "security_alert", "suspicious_activity",  # noqa: E501
        "blocked_request", "admin_action", name="auditaction"  # noqa: E501
    )
    auditseverity = sa.Enum("info", "warning", "critical", name="auditseverity")  # noqa: E501
    notificationtype = sa.Enum("info", "success", "warning", "alert", "security", name="notificationtype")  # noqa: E501
    documentvalidationstatus = sa.Enum("pending", "validating", "passed", "failed_malware", "failed_format", "failed_size", name="documentvalidationstatus")  # noqa: E501
    assettype = sa.Enum("domain", "subdomain", "ip_address", "web_application", "api", "cloud_resource", "mobile_app", "network_range", "other", name="assettype")  # noqa: E501
    alerttype = sa.Enum("anomaly", "brute_force", "intrusion", "exploit_attempt", "data_exfiltration", "policy_violation", name="alerttype")  # noqa: E501
    alertseverity = sa.Enum("critical", "high", "medium", "low", name="alertseverity")  # noqa: E501
    alertstatus = sa.Enum("open", "investigating", "mitigated", "resolved", "false_positive", name="alertstatus")  # noqa: E501

    # Create all enums
    for enum in [userstatus, userrole, engagementstatus, sessionstatus, findingcategory,
                 attackpathstatus, severitylevel, vulnerabilitystatus, risklevel,
                 reportstatus, auditaction, auditseverity, notificationtype,
                 documentvalidationstatus, assettype, alerttype, alertseverity, alertstatus]:
        enum.create(op.get_bind(), checkfirst=True)

    # ─── 1. users ────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("phone_number", sa.String(20), nullable=True),
        sa.Column("profile_image_url", sa.Text, nullable=True),
        sa.Column("company_name", sa.String(255), nullable=False),
        sa.Column("job_title", sa.String(255), nullable=False),
        sa.Column("company_location", sa.String(500), nullable=True),
        sa.Column("company_logo_url", sa.Text, nullable=True),
        sa.Column("hashed_password", sa.Text, nullable=False),
        sa.Column("status", userstatus, nullable=False, server_default="pending_verification"),
        sa.Column("role", userrole, nullable=False, server_default="user"),
        sa.Column("mfa_enabled", sa.Boolean, server_default="false"),
        sa.Column("mfa_secret", sa.Text, nullable=True),
        sa.Column("registration_ip", sa.String(45), nullable=True),
        sa.Column("registration_user_agent", sa.Text, nullable=True),
        sa.Column("registration_browser", sa.String(255), nullable=True),
        sa.Column("registration_os", sa.String(255), nullable=True),
        sa.Column("registration_device", sa.String(255), nullable=True),
        sa.Column("registration_location", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 2. otp_verifications ────────────────────────────────
    op.create_table(
        "otp_verifications",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.String(36), index=True, nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_otp", sa.Text, nullable=False),
        sa.Column("attempts", sa.Integer, server_default="0"),
        sa.Column("max_attempts", sa.Integer, server_default="5"),
        sa.Column("is_used", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 3. verification_codes ───────────────────────────────
    op.create_table(
        "verification_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), index=True, nullable=False),
        sa.Column("code_hash", sa.Text, nullable=False),
        sa.Column("purpose", sa.String(50), server_default="registration"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 4. user_sessions ────────────────────────────────────
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("token_jti", sa.String(255), unique=True, nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("browser", sa.String(255), nullable=True),
        sa.Column("os", sa.String(255), nullable=True),
        sa.Column("device", sa.String(255), nullable=True),
        sa.Column("location", sa.String(500), nullable=True),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 5. engagements ──────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_number", sa.String(20), unique=True, index=True, nullable=False),  # noqa: E501
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("project_name", sa.String(500), nullable=False),
        sa.Column("organization_name", sa.String(500), nullable=False),
        sa.Column("objective", sa.Text, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", engagementstatus, nullable=False, server_default="draft"),
        sa.Column("progress_percentage", sa.Integer, server_default="0"),
        sa.Column("current_phase", sa.String(100), nullable=True),
        sa.Column("risk_level", sa.String(50), nullable=True),
        sa.Column("overall_security_score", sa.Float, nullable=True),
        sa.Column("conversation_history", sa.Text, nullable=True),
        sa.Column("ai_context_model", sa.Text, nullable=True),
        sa.Column("estimated_duration_days", sa.Integer, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 6. scopes_of_engagement ─────────────────────────────
    op.create_table(
        "scopes_of_engagement",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), unique=True, nullable=False),  # noqa: E501
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("testing_objective", sa.Text, nullable=False),
        sa.Column("testing_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("testing_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_non_destructive", sa.Boolean, server_default="true"),
        sa.Column("max_impact_level", sa.String(50), nullable=True),
        sa.Column("maintenance_windows", sa.Text, nullable=True),
        sa.Column("emergency_contact", sa.String(255), nullable=True),
        sa.Column("legal_restrictions", sa.Text, nullable=True),
        sa.Column("compliance_requirements", sa.Text, nullable=True),
        sa.Column("include_osint", sa.Boolean, server_default="true"),
        sa.Column("include_red_team", sa.Boolean, server_default="true"),
        sa.Column("include_risk_assessment", sa.Boolean, server_default="true"),
        sa.Column("include_report_generation", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 7. scope_assets ─────────────────────────────────────
    op.create_table(
        "scope_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope_id", sa.String(36), sa.ForeignKey("scopes_of_engagement.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("asset_type", assettype, nullable=False),
        sa.Column("value", sa.String(1000), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_excluded", sa.Boolean, server_default="false"),
        sa.Column("exclusion_reason", sa.Text, nullable=True),
    )

    # ─── 8. rules_of_engagement ──────────────────────────────
    op.create_table(
        "rules_of_engagement",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), unique=True, nullable=False),  # noqa: E501
        sa.Column("document_html", sa.Text, nullable=False),
        sa.Column("document_text", sa.Text, nullable=False),
        sa.Column("authorization_clause", sa.Text, nullable=False),
        sa.Column("methodology_clause", sa.Text, nullable=False),
        sa.Column("prohibited_actions_clause", sa.Text, nullable=False),
        sa.Column("client_obligations_clause", sa.Text, nullable=False),
        sa.Column("liability_clause", sa.Text, nullable=False),
        sa.Column("confidentiality_clause", sa.Text, nullable=False),
        sa.Column("is_signed", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 9. digital_signatures ───────────────────────────────
    op.create_table(
        "digital_signatures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), unique=True, nullable=False),  # noqa: E501
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("signed_name", sa.String(500), nullable=False),
        sa.Column("cryptographic_hash", sa.Text, nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("pdf_storage_path", sa.Text, nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 10. uploaded_documents ──────────────────────────────
    op.create_table(
        "uploaded_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("original_filename", sa.String(500), nullable=False),
        sa.Column("storage_path", sa.Text, nullable=False),
        sa.Column("file_size_bytes", sa.Integer, nullable=False),
        sa.Column("mime_type", sa.String(100), nullable=False),
        sa.Column("file_hash_sha256", sa.String(64), nullable=False),
        sa.Column("validation_status", documentvalidationstatus, server_default="pending"),  # noqa: E501
        sa.Column("malware_scan_result", sa.Text, nullable=True),
        sa.Column("metadata_extracted", sa.Text, nullable=True),
        sa.Column("validation_notes", sa.Text, nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 11. chat_sessions ───────────────────────────────────
    op.create_table(
        "chat_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True),  # noqa: E501
        sa.Column("status", sessionstatus, server_default="intake"),
        sa.Column("summary_text", sa.Text, nullable=True),
        sa.Column("scope_json", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 12. chat_messages ───────────────────────────────────
    op.create_table(
        "chat_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("chat_sessions.id"), index=True),  # noqa: E501
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 13. osint_findings ──────────────────────────────────
    op.create_table(
        "osint_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("category", findingcategory, nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("confidence_score", sa.Float, server_default="0"),
        sa.Column("raw_data", sa.JSON, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 14. knowledge_graph_nodes ───────────────────────────
    op.create_table(
        "knowledge_graph_nodes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("node_type", sa.String(100), nullable=False),
        sa.Column("label", sa.String(500), nullable=False),
        sa.Column("properties", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 15. knowledge_graph_edges ───────────────────────────
    op.create_table(
        "knowledge_graph_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("source_node_id", sa.String(36), sa.ForeignKey("knowledge_graph_nodes.id"), nullable=False),  # noqa: E501
        sa.Column("target_node_id", sa.String(36), sa.ForeignKey("knowledge_graph_nodes.id"), nullable=False),  # noqa: E501
        sa.Column("relationship_type", sa.String(100), nullable=False),
        sa.Column("weight", sa.Float, server_default="1"),
        sa.Column("properties", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 16. attack_paths ────────────────────────────────────
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("initial_entry_point", sa.Text, nullable=False),
        sa.Column("expected_impact", sa.Text, nullable=False),
        sa.Column("technical_feasibility", sa.Float, server_default="0"),
        sa.Column("business_impact", sa.Float, server_default="0"),
        sa.Column("confidence_score", sa.Float, server_default="0"),
        sa.Column("priority", sa.Integer, server_default="0"),
        sa.Column("status", attackpathstatus, server_default="identified"),
        sa.Column("result_summary", sa.Text, nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 17. attack_path_steps ───────────────────────────────
    op.create_table(
        "attack_path_steps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("attack_path_id", sa.String(36), sa.ForeignKey("attack_paths.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("step_number", sa.Integer, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("tool", sa.String(255), nullable=True),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("success", sa.Boolean, nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 18. vulnerabilities ─────────────────────────────────
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("severity", severitylevel, nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("exploitability_score", sa.Float, server_default="0"),
        sa.Column("business_impact_score", sa.Float, server_default="0"),
        sa.Column("confidence_score", sa.Float, server_default="0"),
        sa.Column("affected_assets", sa.Text, nullable=True),
        sa.Column("affected_component", sa.String(500), nullable=True),
        sa.Column("exploitation_method", sa.Text, nullable=True),
        sa.Column("proof_of_concept", sa.Text, nullable=True),
        sa.Column("raw_technical_data", sa.JSON, nullable=True),
        sa.Column("confidentiality_impact", sa.Text, nullable=True),
        sa.Column("integrity_impact", sa.Text, nullable=True),
        sa.Column("availability_impact", sa.Text, nullable=True),
        sa.Column("estimated_financial_impact", sa.Text, nullable=True),
        sa.Column("remediation_steps", sa.Text, nullable=True),
        sa.Column("remediation_priority", sa.Integer, nullable=True),
        sa.Column("status", vulnerabilitystatus, server_default="confirmed"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 19. vulnerability_evidence ──────────────────────────
    op.create_table(
        "vulnerability_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("evidence_type", sa.String(100), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("screenshot_path", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 20. risk_assessments ────────────────────────────────
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("vulnerability_id", sa.String(36), sa.ForeignKey("vulnerabilities.id"), nullable=False),  # noqa: E501
        sa.Column("risk_level", risklevel, nullable=False),
        sa.Column("likelihood_of_exploitation", sa.Float, server_default="0"),
        sa.Column("complexity_required", sa.String(100), nullable=True),
        sa.Column("privileges_obtainable", sa.Text, nullable=True),
        sa.Column("asset_sensitivity", sa.Float, server_default="0"),
        sa.Column("cumulative_risk_score", sa.Float, server_default="0"),
        sa.Column("potential_consequences", sa.JSON, nullable=True),
        sa.Column("affected_services", sa.Text, nullable=True),
        sa.Column("regulatory_implications", sa.Text, nullable=True),
        sa.Column("remediation_priority", sa.Integer, server_default="0"),
        sa.Column("estimated_remediation_effort", sa.String(100), nullable=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 21. reports ─────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=False),  # noqa: E501
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("version", sa.String(20), server_default="1.0"),
        sa.Column("overall_security_score", sa.Float, server_default="0"),
        sa.Column("total_findings", sa.Integer, server_default="0"),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("executive_summary", sa.Text, nullable=True),
        sa.Column("methodology", sa.Text, nullable=True),
        sa.Column("detailed_findings", sa.Text, nullable=True),
        sa.Column("remediation_roadmap", sa.Text, nullable=True),
        sa.Column("overall_assessment", sa.Text, nullable=True),
        sa.Column("pdf_storage_path", sa.Text, nullable=True),
        sa.Column("status", reportstatus, server_default="generating"),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("emailed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 22. audit_logs ──────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), index=True, nullable=True),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), index=True, nullable=True),  # noqa: E501
        sa.Column("action", auditaction, nullable=False),
        sa.Column("severity", auditseverity, server_default="info"),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("request_method", sa.String(10), nullable=True),
        sa.Column("request_path", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),  # noqa: E501
    )

    # ─── 23. immutable_logs ──────────────────────────────────
    op.create_table(
        "immutable_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("log_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=True),
        sa.Column("content", sa.JSON, nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("actor_type", sa.String(20), server_default="user"),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 24. ip_logs ─────────────────────────────────────────
    op.create_table(
        "ip_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=True, index=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("ip_version", sa.Integer, server_default="4"),
        sa.Column("geo_country", sa.String(100), nullable=True),
        sa.Column("geo_city", sa.String(100), nullable=True),
        sa.Column("geo_lat", sa.Float, nullable=True),
        sa.Column("geo_lon", sa.Float, nullable=True),
        sa.Column("device_fingerprint", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("browser", sa.String(100), nullable=True),
        sa.Column("os", sa.String(100), nullable=True),
        sa.Column("device_type", sa.String(50), nullable=True),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("risk_score", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 25. security_alerts ─────────────────────────────────
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_type", alerttype, nullable=False),
        sa.Column("severity", alertseverity, nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("engagement_id", sa.String(36), nullable=True),
        sa.Column("related_user_id", sa.String(36), nullable=True),
        sa.Column("evidence_refs", sa.JSON, nullable=True),
        sa.Column("status", alertstatus, server_default="open"),
        sa.Column("auto_defense_actions", sa.JSON, nullable=True),
        sa.Column("assigned_to", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 26. incidents ───────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("security_alerts.id"), nullable=True),  # noqa: E501
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", alertseverity, nullable=False),
        sa.Column("timeline", sa.JSON, nullable=True),
        sa.Column("affected_resources", sa.JSON, nullable=True),
        sa.Column("root_cause", sa.Text, nullable=True),
        sa.Column("lessons_learned", sa.Text, nullable=True),
        sa.Column("status", sa.String(50), server_default="detected"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 27. blocked_ips ─────────────────────────────────────
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("ip_range", sa.String(50), nullable=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("blocked_by", sa.String(50), server_default="system"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("unblocked_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ─── 28. system_metrics ──────────────────────────────────
    op.create_table(
        "system_metrics",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("metric_name", sa.String(100), nullable=False),
        sa.Column("value", sa.Float, nullable=False),
        sa.Column("unit", sa.String(20), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ─── 29. notifications ───────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), index=True, nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), nullable=True),  # noqa: E501
        sa.Column("notification_type", notificationtype, server_default="info"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("action_url", sa.Text, nullable=True),
        sa.Column("is_read", sa.Boolean, server_default="false"),
        sa.Column("is_emailed", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    tables = [
        "notifications", "system_metrics", "blocked_ips", "incidents",
        "security_alerts", "ip_logs", "immutable_logs", "audit_logs",
        "reports", "risk_assessments", "vulnerability_evidence",
        "vulnerabilities", "attack_path_steps", "attack_paths",
        "knowledge_graph_edges", "knowledge_graph_nodes", "osint_findings",
        "chat_messages", "chat_sessions", "uploaded_documents",
        "digital_signatures", "rules_of_engagement", "scope_assets",
        "scopes_of_engagement", "engagements", "user_sessions",
        "verification_codes", "otp_verifications", "users",
    ]
    for table in tables:
        op.drop_table(table)

    # Drop enums
    enum_names = [
        "alertstatus", "alertseverity", "alerttype", "assettype",
        "documentvalidationstatus", "notificationtype", "auditseverity",
        "auditaction", "reportstatus", "risklevel", "vulnerabilitystatus",
        "severitylevel", "attackpathstatus", "findingcategory",
        "sessionstatus", "engagementstatus", "userrole", "userstatus",
    ]
    for name in enum_names:
        op.execute(f"DROP TYPE IF EXISTS {name}")
