"""
IP Logger — IP + GeoIP + Device fingerprint + Browser fingerprint logging.
"""

from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()


class IPLogger:
    """Records comprehensive client metadata for security auditing."""

    @staticmethod
    def extract_client_info(request) -> dict:
        """Extract all available client metadata from a request."""
        ip = request.client.host if request.client else "unknown"
        ua = request.headers.get("user-agent", "")
        forwarded = request.headers.get("x-forwarded-for", "")
        real_ip = forwarded.split(",")[0].strip() if forwarded else ip

        from app.utils.user_agent import parse_user_agent
        ua_info = parse_user_agent(ua)

        return {
            "ip_address": real_ip,
            "user_agent": ua[:500],
            "browser": ua_info.get("browser"),
            "os": ua_info.get("os"),
            "device": ua_info.get("device"),
            "accept_language": request.headers.get("accept-language", "")[:100],
            "referer": request.headers.get("referer", "")[:500],
            "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }
