"""OSINT Tools — WHOIS, DNS, subdomain enumeration, email harvest."""

import httpx
import structlog

logger = structlog.get_logger()


class OSINTTools:
    """Collection of OSINT tools for intelligence gathering."""

    async def dns_lookup(self, domain: str, record_type: str = "A") -> list[str]:
        """DNS record lookup using DoH (DNS over HTTPS)."""
        try:
            url = (
                f"https://cloudflare-dns.com/dns-query?name={domain}"
                f"&type={record_type}"
            )
            headers = {"accept": "application/dns-json"}
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=10)
                data = resp.json()
                return [a["data"] for a in data.get("Answer", [])]
        except Exception as e:
            logger.error("dns_lookup_error", domain=domain, error=str(e))
            return []

    async def certificate_transparency(self, domain: str) -> list[str]:
        """Search crt.sh for subdomains via certificate transparency logs."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json", timeout=30
                )
                if resp.status_code == 200:
                    certs = resp.json()
                    subdomains = set()
                    for c in certs[:200]:
                        for name in c.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(domain) and "*" not in name:
                                subdomains.add(name)
                    return sorted(subdomains)
        except Exception as e:
            logger.error("ct_error", error=str(e))
        return []

    async def web_archive_search(self, domain: str, limit: int = 100) -> list[dict]:
        """Search Wayback Machine for archived snapshots."""
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}&output=json&limit={limit}"
                f"&fl=timestamp,original,statuscode"
            )
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {"timestamp": r[0], "url": r[1], "status": r[2]}
                        for r in data[1:]
                    ]
        except Exception as e:
            logger.error("archive_error", error=str(e))
        return []

    async def github_search(self, query: str, per_page: int = 10) -> list[dict]:
        """Search GitHub for public repositories."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/search/repositories"
                    f"?q={query}&per_page={per_page}",
                    timeout=15,
                )
                if resp.status_code == 200:
                    return [
                        {
                            "name": r["full_name"],
                            "description": r.get("description"),
                            "url": r["html_url"],
                        }
                        for r in resp.json().get("items", [])
                    ]
        except Exception as e:
            logger.error("github_search_error", error=str(e))
        return []

    async def http_headers(self, url: str) -> dict:
        """Fetch HTTP headers to detect technologies."""
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(url, timeout=10)
                return dict(resp.headers)
        except Exception as e:
            logger.error("headers_error", url=url, error=str(e))
        return {}
