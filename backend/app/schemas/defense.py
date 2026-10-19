"""
Defense Schemas — Request/Response models for Blue Team defense endpoints.
"""

from datetime import datetime

from pydantic import BaseModel


class TierStatus(BaseModel):
    tier_name: str
    tier_number: int
    status: str
    requests_inspected: int
    threats_blocked: int
    description: str


class SecurityAlertItem(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    source_ip: str | None
    attack_type: str | None
    blocked: bool
    created_at: datetime
    # ─── Explainability (Tier 2 Part B) ────────────────────
    # WHY this alert fired: the detector's own reasons (e.g.
    # "High request rate: decayed weight 62.3 over 60s").
    reasons: list[str] = []
    # Detector confidence in the decision, 0.0–1.0
    # (heuristic/behavioral: the risk score itself; deterministic
    # counter rules: their fixed confidence).
    risk_score: float | None = None
    confidence: float | None = None
    # Correlated identity when the session was authenticated
    # (session key: user:<id> or ip:<ip>).
    session: str | None = None


class DefenseDashboardResponse(BaseModel):
    success: bool = True
    system_health: str
    uptime_percentage: float
    total_requests_today: int
    threats_blocked_today: int
    active_sessions: int
    suspicious_sessions: int
    tiers: list[TierStatus]
    recent_alerts: list[SecurityAlertItem]


class SecurityAlertListResponse(BaseModel):
    success: bool = True
    total: int
    items: list[SecurityAlertItem]


class ThreatPatternItem(BaseModel):
    pattern_name: str
    occurrences: int
    last_seen: datetime
    severity: str


class ThreatIntelligenceResponse(BaseModel):
    success: bool = True
    active_threat_patterns: list[ThreatPatternItem]
    blocked_ips: int
    virtual_patches_applied: int
    firewall_rules_updated: int


class MonitoringStatusResponse(BaseModel):
    success: bool = True
    monitoring_active: bool
    last_scan: datetime
    next_scan: datetime
    active_alerts: int
    resolved_alerts_today: int
    remediation_progress: float


# ─── Defense Metrics ──────────────────────────────────────────

class DefenseMetricsResponse(BaseModel):
    """Defense middleware metrics."""
    success: bool = True
    requests_inspected: int
    threats_blocked: int
    rate_limit_blocked: int
    input_validation_blocked: int
    abuse_blocked: int
    behavioral_anomalies: int
    blocked_ips_count: int
    defense_enabled: bool
    rate_limit: int
    rate_window: int
    max_failed_logins: int
    max_403_errors: int


# ─── Blocked IPs ──────────────────────────────────────────────

class BlockedIPItem(BaseModel):
    """A single blocked IP entry."""
    ip: str
    expires_in: int
    blocked: bool = True


class BlockedIPListResponse(BaseModel):
    """List of blocked IPs."""
    success: bool = True
    total: int
    items: list[BlockedIPItem]


class BlockIPRequest(BaseModel):
    """Request to block an IP."""
    ip: str
    duration_seconds: int = 3600
    reason: str = ""


class BlockIPResponse(BaseModel):
    """Response after blocking an IP."""
    success: bool = True
    message: str
    ip: str
    duration_seconds: int


class UnblockIPResponse(BaseModel):
    """Response after unblocking an IP."""
    success: bool = True
    message: str
    ip: str


# ─── Incidents ────────────────────────────────────────────────

class IncidentItem(BaseModel):
    """A single security incident."""
    ip: str
    type: str
    details: str
    timestamp: str
    unix_timestamp: float


class IncidentListResponse(BaseModel):
    """List of security incidents."""
    success: bool = True
    total: int
    items: list[IncidentItem]


# ─── Anomaly Status ───────────────────────────────────────────

class AnomalyStatusResponse(BaseModel):
    """Anomaly detection status for an IP."""
    success: bool = True
    ip: str
    is_anomaly: bool
    score: float
    method: str
    reason: str | None = None
    reasons: list[str] = []
    risk_score: float = 0.0
    anomaly_detected: bool = False