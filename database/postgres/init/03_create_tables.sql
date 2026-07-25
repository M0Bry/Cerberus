-- Cerberus AI — Initial Schema (Bootstrap)
-- Note: In production, use Alembic migrations instead.
-- This file is only for Docker first-boot initialization.

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    status VARCHAR(50) DEFAULT 'pending_verification',
    full_name VARCHAR(255), phone VARCHAR(50), company_name VARCHAR(255),
    job_title VARCHAR(255), company_address TEXT, avatar_url TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE, mfa_secret TEXT,
    registration_ip VARCHAR(45), registration_user_agent TEXT,
    registration_browser VARCHAR(255), registration_os VARCHAR(255),
    registration_device VARCHAR(255), registration_location TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ, verified_at TIMESTAMPTZ
);

-- OTP Verifications
CREATE TABLE IF NOT EXISTS otp_verifications (
    id SERIAL PRIMARY KEY, user_id UUID NOT NULL, email VARCHAR(255) NOT NULL,
    hashed_otp TEXT NOT NULL, attempts INT DEFAULT 0, max_attempts INT DEFAULT 5,
    is_used BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
);

-- Verification Codes
CREATE TABLE IF NOT EXISTS verification_codes (
    id UUID PRIMARY KEY, user_id UUID NOT NULL, code_hash TEXT NOT NULL,
    purpose VARCHAR(50) DEFAULT 'registration', expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ, attempts_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- User Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY, user_id UUID REFERENCES users(id),
    token_jti VARCHAR(255) UNIQUE NOT NULL, ip_address VARCHAR(45),
    user_agent TEXT, browser VARCHAR(255), os VARCHAR(255),
    device VARCHAR(255), location TEXT, is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ
);

-- Engagements
CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY, engagement_number VARCHAR(20) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id), project_name VARCHAR(500) NOT NULL,
    organization_name VARCHAR(500) NOT NULL, objective TEXT, description TEXT,
    status VARCHAR(50) DEFAULT 'draft', progress_percentage INT DEFAULT 0,
    current_phase VARCHAR(100), risk_level VARCHAR(50),
    overall_security_score FLOAT, conversation_history TEXT,
    ai_context_model TEXT, estimated_duration_days INT,
    started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scope of Engagement
CREATE TABLE IF NOT EXISTS scopes_of_engagement (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id) UNIQUE,
    summary TEXT NOT NULL, testing_objective TEXT NOT NULL,
    testing_period_start TIMESTAMPTZ, testing_period_end TIMESTAMPTZ,
    is_non_destructive BOOLEAN DEFAULT TRUE, max_impact_level VARCHAR(50),
    maintenance_windows TEXT, emergency_contact VARCHAR(255),
    legal_restrictions TEXT, compliance_requirements TEXT,
    include_osint BOOLEAN DEFAULT TRUE, include_red_team BOOLEAN DEFAULT TRUE,
    include_risk_assessment BOOLEAN DEFAULT TRUE, include_report_generation BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(), approved_at TIMESTAMPTZ
);

-- Scope Assets
CREATE TABLE IF NOT EXISTS scope_assets (
    id UUID PRIMARY KEY, scope_id UUID REFERENCES scopes_of_engagement(id),
    asset_type VARCHAR(50) NOT NULL, value VARCHAR(1000) NOT NULL,
    description TEXT, is_excluded BOOLEAN DEFAULT FALSE, exclusion_reason TEXT
);

-- Chat Sessions
CREATE TABLE IF NOT EXISTS chat_sessions (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    status VARCHAR(50) DEFAULT 'intake', summary_text TEXT,
    scope_json TEXT, created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Chat Messages
CREATE TABLE IF NOT EXISTS chat_messages (
    id UUID PRIMARY KEY, session_id UUID REFERENCES chat_sessions(id),
    role VARCHAR(20) NOT NULL, content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Rules of Engagement
CREATE TABLE IF NOT EXISTS rules_of_engagement (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id) UNIQUE,
    document_html TEXT NOT NULL, document_text TEXT NOT NULL,
    authorization_clause TEXT NOT NULL, methodology_clause TEXT NOT NULL,
    prohibited_actions_clause TEXT NOT NULL, client_obligations_clause TEXT NOT NULL,
    liability_clause TEXT NOT NULL, confidentiality_clause TEXT NOT NULL,
    is_signed BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW(),
    signed_at TIMESTAMPTZ
);

-- Digital Signatures
CREATE TABLE IF NOT EXISTS digital_signatures (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id) UNIQUE,
    user_id UUID REFERENCES users(id), signed_name VARCHAR(500) NOT NULL,
    cryptographic_hash TEXT NOT NULL, ip_address VARCHAR(45),
    user_agent TEXT, pdf_storage_path TEXT,
    signed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Uploaded Documents
CREATE TABLE IF NOT EXISTS uploaded_documents (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    original_filename VARCHAR(500) NOT NULL, storage_path TEXT NOT NULL,
    file_size_bytes INT NOT NULL, mime_type VARCHAR(100) NOT NULL,
    file_hash_sha256 VARCHAR(64) NOT NULL, validation_status VARCHAR(50) DEFAULT 'pending',
    malware_scan_result TEXT, metadata_extracted TEXT, validation_notes TEXT,
    uploaded_at TIMESTAMPTZ DEFAULT NOW(), validated_at TIMESTAMPTZ
);

-- OSINT Findings
CREATE TABLE IF NOT EXISTS osint_findings (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    category VARCHAR(50) NOT NULL, title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL, evidence TEXT, source_url TEXT,
    confidence_score FLOAT DEFAULT 0, raw_data JSONB,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

-- Knowledge Graph
CREATE TABLE IF NOT EXISTS knowledge_graph_nodes (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    node_type VARCHAR(100) NOT NULL, label VARCHAR(500) NOT NULL,
    properties JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS knowledge_graph_edges (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    source_node_id UUID REFERENCES knowledge_graph_nodes(id),
    target_node_id UUID REFERENCES knowledge_graph_nodes(id),
    relationship_type VARCHAR(100) NOT NULL, weight FLOAT DEFAULT 1,
    properties JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Attack Paths
CREATE TABLE IF NOT EXISTS attack_paths (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    name VARCHAR(500) NOT NULL, description TEXT NOT NULL,
    initial_entry_point TEXT NOT NULL, expected_impact TEXT NOT NULL,
    technical_feasibility FLOAT DEFAULT 0, business_impact FLOAT DEFAULT 0,
    confidence_score FLOAT DEFAULT 0, priority INT DEFAULT 0,
    status VARCHAR(50) DEFAULT 'identified', result_summary TEXT, evidence TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(), executed_at TIMESTAMPTZ, completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attack_path_steps (
    id UUID PRIMARY KEY, attack_path_id UUID REFERENCES attack_paths(id),
    step_number INT NOT NULL, action TEXT NOT NULL, tool VARCHAR(255),
    result TEXT, evidence TEXT, success BOOLEAN, executed_at TIMESTAMPTZ
);

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    title VARCHAR(500) NOT NULL, description TEXT NOT NULL,
    category VARCHAR(100) NOT NULL, cve_id VARCHAR(50),
    severity VARCHAR(20) NOT NULL, cvss_score FLOAT,
    exploitability_score FLOAT DEFAULT 0, business_impact_score FLOAT DEFAULT 0,
    confidence_score FLOAT DEFAULT 0, affected_assets TEXT,
    affected_component VARCHAR(500), exploitation_method TEXT,
    proof_of_concept TEXT, raw_technical_data JSONB,
    confidentiality_impact TEXT, integrity_impact TEXT, availability_impact TEXT,
    estimated_financial_impact TEXT, remediation_steps TEXT,
    remediation_priority INT, status VARCHAR(50) DEFAULT 'confirmed',
    discovered_at TIMESTAMPTZ DEFAULT NOW(), validated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS vulnerability_evidence (
    id UUID PRIMARY KEY, vulnerability_id UUID REFERENCES vulnerabilities(id),
    evidence_type VARCHAR(100) NOT NULL, description TEXT NOT NULL,
    content TEXT NOT NULL, screenshot_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Risk Assessments
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    risk_level VARCHAR(20) NOT NULL, likelihood_of_exploitation FLOAT DEFAULT 0,
    complexity_required VARCHAR(100), privileges_obtainable TEXT,
    asset_sensitivity FLOAT DEFAULT 0, cumulative_risk_score FLOAT DEFAULT 0,
    potential_consequences JSONB, affected_services TEXT,
    regulatory_implications TEXT, remediation_priority INT DEFAULT 0,
    estimated_remediation_effort VARCHAR(100),
    assessed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reports
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY, engagement_id UUID REFERENCES engagements(id),
    title VARCHAR(500) NOT NULL, version VARCHAR(20) DEFAULT '1.0',
    overall_security_score FLOAT DEFAULT 0, total_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0, high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0, low_count INT DEFAULT 0,
    executive_summary TEXT, methodology TEXT, detailed_findings TEXT,
    remediation_roadmap TEXT, overall_assessment TEXT, pdf_storage_path TEXT,
    status VARCHAR(50) DEFAULT 'generating',
    generated_at TIMESTAMPTZ DEFAULT NOW(), emailed_at TIMESTAMPTZ
);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY, user_id UUID, engagement_id UUID,
    action VARCHAR(100) NOT NULL, severity VARCHAR(20) DEFAULT 'info',
    description TEXT NOT NULL, details JSONB,
    ip_address VARCHAR(45), user_agent TEXT,
    request_method VARCHAR(10), request_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Immutable Logs
CREATE TABLE IF NOT EXISTS immutable_logs (
    id UUID PRIMARY KEY, log_hash VARCHAR(64) UNIQUE NOT NULL,
    previous_hash VARCHAR(64), content JSONB NOT NULL,
    signature TEXT NOT NULL, actor_id UUID, actor_type VARCHAR(20) DEFAULT 'user',
    resource_type VARCHAR(50), resource_id UUID,
    ip_address VARCHAR(45), user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- IP Logs
CREATE TABLE IF NOT EXISTS ip_logs (
    id UUID PRIMARY KEY, user_id UUID, ip_address VARCHAR(45) NOT NULL,
    ip_version INT DEFAULT 4, geo_country VARCHAR(100), geo_city VARCHAR(100),
    geo_lat FLOAT, geo_lon FLOAT, device_fingerprint TEXT,
    user_agent TEXT, browser VARCHAR(100), os VARCHAR(100),
    device_type VARCHAR(50), action VARCHAR(50) NOT NULL,
    risk_score INT DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Security Alerts
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY, alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL, title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL, source_ip VARCHAR(45),
    engagement_id UUID, related_user_id UUID,
    evidence_refs JSONB, status VARCHAR(50) DEFAULT 'open',
    auto_defense_actions JSONB, assigned_to UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(), resolved_at TIMESTAMPTZ
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY, alert_id UUID REFERENCES security_alerts(id),
    title VARCHAR(500) NOT NULL, description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL, timeline JSONB,
    affected_resources JSONB, root_cause TEXT, lessons_learned TEXT,
    status VARCHAR(50) DEFAULT 'detected',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Blocked IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY, ip_address VARCHAR(45) NOT NULL,
    ip_range VARCHAR(50), reason TEXT NOT NULL,
    blocked_by VARCHAR(50) DEFAULT 'system',
    expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW(),
    unblocked_at TIMESTAMPTZ
);

-- System Metrics
CREATE TABLE IF NOT EXISTS system_metrics (
    id UUID PRIMARY KEY, metric_name VARCHAR(100) NOT NULL,
    value FLOAT NOT NULL, unit VARCHAR(20) NOT NULL,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY, user_id UUID REFERENCES users(id),
    engagement_id UUID, notification_type VARCHAR(50) DEFAULT 'info',
    title VARCHAR(500) NOT NULL, message TEXT NOT NULL,
    action_url TEXT, is_read BOOLEAN DEFAULT FALSE,
    is_emailed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(), read_at TIMESTAMPTZ
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_engagements_user ON engagements(user_id);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_osint_findings_engagement ON osint_findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_engagement ON vulnerabilities(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
