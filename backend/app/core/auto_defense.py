"""
Auto Defense — Automated firewall rules, IP blocking, alert generation.
"""

import time

import structlog

logger = structlog.get_logger()


class AutoDefense:
    """Automated defensive responses to detected threats."""

    def __init__(self) -> None:
        self._blocked_ips: dict[str, float] = {}  # ip → unblock_timestamp
        self._firewall_rules: list[dict] = []

    def block_ip(
        self,
        ip: str,
        duration_seconds: int = 3600,
        reason: str = "",
    ) -> dict:
        """Block an IP address for a specified duration."""
        now = time.time()
        self._blocked_ips[ip] = now + duration_seconds
        rule = {
            "ip": ip,
            "duration": duration_seconds,
            "reason": reason,
            "blocked_at": now,
        }
        self._firewall_rules.append(rule)
        logger.warning(
            "ip_blocked", ip=ip, duration=duration_seconds, reason=reason
        )
        return rule

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        expiry = self._blocked_ips.get(ip)
        if expiry and time.time() < expiry:
            return True
        if expiry:
            del self._blocked_ips[ip]
        return False

    def add_waf_rule(
        self,
        pattern: str,
        action: str = "block",
        description: str = "",
    ) -> dict:
        """Add a WAF rule to block a specific pattern."""
        rule = {
            "pattern": pattern,
            "action": action,
            "description": description,
            "active": True,
        }
        self._firewall_rules.append(rule)
        logger.info("waf_rule_added", pattern=pattern, action=action)
        return rule

    def get_blocked_ips(self) -> list[dict]:
        """Get all currently blocked IPs."""
        now = time.time()
        return [
            {"ip": ip, "expires_in": int(expiry - now)}
            for ip, expiry in self._blocked_ips.items()
            if expiry > now
        ]

    def generate_alert(
        self,
        severity: str,
        title: str,
        description: str,
        source_ip: str | None = None,
    ) -> dict:
        """Generate a security alert."""
        alert = {
            "severity": severity,
            "title": title,
            "description": description,
            "source_ip": source_ip,
            "timestamp": time.time(),
            "auto_actions": self._get_recommended_actions(severity),
        }
        logger.warning(
            "security_alert",
            severity=severity,
            title=title,
            source_ip=source_ip,
        )
        return alert

    def _get_recommended_actions(self, severity: str) -> list[str]:
        if severity == "critical":
            return [
                "Block source IP",
                "Notify security team",
                "Create incident",
                "Apply virtual patch",
            ]
        elif severity == "high":
            return [
                "Monitor source IP",
                "Notify security team",
                "Increase logging",
            ]
        return ["Log event", "Monitor pattern"]
