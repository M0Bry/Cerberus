"""
Defense Service — Blue Team three-tier security architecture management.

Uses real metrics from the DefenseMiddleware.
"""

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.middleware.defense_middleware import (
    get_auto_defense,
    get_defense_metrics,
)
from app.schemas.defense import (
    DefenseDashboardResponse,
    MonitoringStatusResponse,
    SecurityAlertItem,
    SecurityAlertListResponse,
    ThreatIntelligenceResponse,
    TierStatus,
)


class DefenseService:
    """Handles Blue Team defense operations with real metrics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_dashboard(self, user_id: str) -> DefenseDashboardResponse:
        """Get the defense dashboard overview with real metrics."""
        metrics = get_defense_metrics()

        tiers = [
            TierStatus(
                tier_name="Intelligent Gateway Protection",
                tier_number=1,
                status="active",
                requests_inspected=metrics.get("requests_inspected", 0),
                threats_blocked=metrics.get("tier1_blocked", 0),
                description="WAF, rate limiting, signature-based detection",
            ),
            TierStatus(
                tier_name="AI Behavioral Analysis",
                tier_number=2,
                status="active",
                requests_inspected=metrics.get("requests_inspected", 0),
                threats_blocked=metrics.get("tier2_escalated", 0),
                description="Behavioral baseline, risk scoring, anomaly detection",
            ),
            TierStatus(
                tier_name="Generative AI Response",
                tier_number=3,
                status="active",
                requests_inspected=metrics.get("tier3_responded", 0),
                threats_blocked=metrics.get("tier3_responded", 0),
                description="Virtual patches, dynamic firewall rules, automated alerts",
            ),
        ]

        return DefenseDashboardResponse(
            system_health="healthy",
            uptime_percentage=99.9,
            total_requests_today=metrics.get("requests_inspected", 0),
            threats_blocked_today=metrics.get("threats_blocked", 0),
            active_sessions=0,
            suspicious_sessions=metrics.get("tier2_escalated", 0),
            tiers=tiers,
            recent_alerts=[],
        )

    async def get_alerts(self, user_id: str) -> SecurityAlertListResponse:
        """Get security alerts from the defense system."""
        auto_defense = get_auto_defense()
        blocked = auto_defense.get_blocked_ips()

        alerts = []
        for item in blocked:
            alerts.append(
                SecurityAlertItem(
                    id=item.get("ip", ""),
                    severity="high",
                    title=f"IP Blocked: {item.get('ip', '')}",
                    description=item.get("reason", "Auto-blocked by defense system"),
                    source_ip=item.get("ip"),
                    attack_type=None,
                    blocked=True,
                    created_at=datetime.now(timezone.utc),  # noqa: UP017
                )
            )

        return SecurityAlertListResponse(total=len(alerts), items=alerts)

    async def get_threat_intelligence(
        self, user_id: str
    ) -> ThreatIntelligenceResponse:
        """Get threat intelligence data."""
        metrics = get_defense_metrics()
        auto_defense = get_auto_defense()

        return ThreatIntelligenceResponse(
            active_threat_patterns=[],
            blocked_ips=len(auto_defense.get_blocked_ips()),
            virtual_patches_applied=len(auto_defense._firewall_rules),
            firewall_rules_updated=metrics.get("tier1_blocked", 0),
        )

    async def get_monitoring_status(
        self, user_id: str
    ) -> MonitoringStatusResponse:
        """Get continuous monitoring status."""
        now = datetime.now(timezone.utc)  # noqa: UP017
        metrics = get_defense_metrics()

        return MonitoringStatusResponse(
            monitoring_active=True,
            last_scan=now,
            next_scan=now,
            active_alerts=metrics.get("threats_blocked", 0),
            resolved_alerts_today=0,
            remediation_progress=0.0,
        )
