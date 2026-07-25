"""Network Utilities — DNS, HTTP, and connection helpers."""

import asyncio

import httpx
import structlog

logger = structlog.get_logger()


async def http_get(url: str, timeout: int = 10, follow_redirects: bool = True) -> dict:
    """Make an HTTP GET request and return response data."""
    try:
        async with httpx.AsyncClient(follow_redirects=follow_redirects) as client:
            resp = await client.get(url, timeout=timeout)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_length": len(resp.content),
                "url": str(resp.url),
            }
    except Exception as e:
        return {"error": str(e)}


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        return True
    except Exception:
        return False


async def resolve_dns(domain: str, record_type: str = "A") -> list[str]:
    """Resolve DNS records using DoH."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}",
                headers={"accept": "application/dns-json"},
                timeout=10,
            )
            data = resp.json()
            return [a["data"] for a in data.get("Answer", [])]
    except Exception:
        return []
