"""Network Isolation — Controls network access for sandbox containers."""

import structlog

logger = structlog.get_logger()


class NetworkIsolation:
    """Manages network isolation for sandboxed tool execution."""

    @staticmethod
    def get_policy(engagement_id: str) -> dict:
        """Get network policy for a sandbox."""
        return {
            "mode": "restricted",
            "allowed_domains": [],  # Only target domains
            "blocked_ports": [22, 3389, 445],  # Block dangerous ports
            "max_connections": 100,
            "rate_limit": "10mbps",
            "dns_overrides": {},
        }

    @staticmethod
    def create_network_name(engagement_id: str) -> str:
        return f"cerberus-sandbox-{engagement_id[:8]}"
