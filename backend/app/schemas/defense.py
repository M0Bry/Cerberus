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
