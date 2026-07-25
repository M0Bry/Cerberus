"""GeoIP Lookup — IP geolocation using free API."""

import httpx
import structlog

logger = structlog.get_logger()


async def lookup_ip(ip: str) -> dict:
    """Look up geolocation for an IP address."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                }
    except Exception as e:
        logger.error("geoip_error", ip=ip, error=str(e))
    return {"country": None, "city": None, "lat": None, "lon": None}
