"""IP Capture — forensic IP, geolocation and device-fingerprint records.

The platform silently records the user's IP + approximate location + device
information at registration, verification and login. This data is stored in
the ``ip_logs`` table and is used for security auditing, anomaly detection
and forensic investigations.

The capture is *fail-soft*: any problem (network, geo service down, private
IP) is logged and swallowed — it must never break the user flow.
"""

import hashlib
import ipaddress
import uuid
from datetime import datetime, timezone  # noqa: F401 (kept for model parity)

import httpx
import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.ip_log import IPLog
from app.utils.user_agent import parse_user_agent

logger = structlog.get_logger()

# Geo lookup must never make the user wait.
_GEO_TIMEOUT_SECONDS = 2.5
_GEO_URL = "https://ipapi.co/{ip}/json/"


def client_ip(request: Request) -> str | None:
    """
    Best-effort client IP.

    X-Forwarded-For is only honoured when the direct TCP peer is one of
    our own trusted proxies (TRUSTED_PROXY_CIDRS) — see
    ``app/core/ip_resolver.py``. From any other peer the header is
    client-controllable and is ignored entirely (anti-spoofing).
    """
    from app.core.ip_resolver import resolve_client_ip

    ip = resolve_client_ip(
        request.client.host if request.client else None, request.headers
    )
    return ip or None


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


async def _lookup_geo(ip: str) -> dict:
    """Resolve approximate city/country for a public IP. Fail-soft."""
    if not _is_public_ip(ip):
        return {}
    try:
        async with httpx.AsyncClient(timeout=_GEO_TIMEOUT_SECONDS) as http:
            resp = await http.get(_GEO_URL.format(ip=ip))
        if resp.status_code != 200:
            return {}
        data = resp.json()
        return {
            "geo_country": data.get("country_name"),
            "geo_city": data.get("city"),
            "geo_lat": data.get("latitude"),
            "geo_lon": data.get("longitude"),
        }
    except Exception as exc:  # noqa: BLE001 — never break the flow
        logger.warning("geo_lookup_failed", ip=ip, error=str(exc))
        return {}


def _fingerprint(request: Request) -> str:
    """Light device fingerprint: hash of UA + platform + language hints."""
    source = "|".join(
        [
            request.headers.get("user-agent", ""),
            request.headers.get("sec-ch-ua-platform", ""),
            request.headers.get("accept-language", ""),
        ]
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


async def record_ip_event(
    db: AsyncSession,
    request: Request,
    user_id: str | None,
    action: str,
) -> None:
    """Store one IPLog row for the given action. Fail-soft by design."""
    try:
        ip = client_ip(request)
        if not ip:
            return

        ua = request.headers.get("user-agent", "")
        ua_info = parse_user_agent(ua)
        geo = await _lookup_geo(ip)

        db.add(
            IPLog(
                id=str(uuid.uuid4()),
                user_id=user_id,
                ip_address=ip,
                ip_version=6 if ":" in ip else 4,
                **geo,
                device_fingerprint=_fingerprint(request),
                user_agent=ua or None,
                browser=ua_info.get("browser"),
                os=ua_info.get("os"),
                device_type=ua_info.get("device"),
                action=action,
            )
        )
        await db.flush()
        logger.info("ip_event_recorded", user_id=user_id, action=action, ip=ip)
    except Exception as exc:  # noqa: BLE001 — forensic capture must not 500 the flow
        logger.warning("ip_capture_failed", action=action, error=str(exc))
