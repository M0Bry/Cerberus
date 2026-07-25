"""
Domain Intelligence — DNS, WHOIS, certificate transparency, subdomain enumeration.
"""

import asyncio

import aiohttp
import structlog

from osint_framework.core import IntelligenceResult
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class DomainIntelligence(OSINTPlugin):
    """
    Comprehensive domain intelligence gathering.

    Sources:
    - DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA)
    - Certificate Transparency logs (crt.sh)
    - WHOIS data
    - Subdomain enumeration
    - Technology fingerprinting (HTTP headers)
    - Wayback Machine archives
    """

    def __init__(self):
        super().__init__()
        self.name = "domain_intel"
        self.description = "Comprehensive domain intelligence gathering"
        self.category = "cybint"

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Execute comprehensive domain intelligence gathering."""
        logger.info("domain_intel_started", target=target)

        domain = target.replace("http://", "").replace("https://", "").split("/")[0]

        # Run all collection tasks in parallel
        results = await asyncio.gather(
            self._dns_lookup(domain),
            self._certificate_transparency(domain),
            self._http_headers(domain),
            self._web_archive(domain),
            return_exceptions=True,
        )

        dns_records = results[0] if not isinstance(results[0], Exception) else {}
        subdomains = results[1] if not isinstance(results[1], Exception) else []
        tech_stack = results[2] if not isinstance(results[2], Exception) else {}
        archive_data = results[3] if not isinstance(results[3], Exception) else []

        # Extract technologies from headers
        technologies = []
        if isinstance(tech_stack, dict):
            server = tech_stack.get("server")
            if server:
                technologies.append(server)
            powered_by = tech_stack.get("x-powered-by")
            if powered_by:
                technologies.append(powered_by)

        processed = {
            "domain": domain,
            "dns_records": dns_records,
            "subdomains": subdomains[:200],
            "technologies": technologies,
            "http_headers": tech_stack,
            "archive_snapshots": len(archive_data) if isinstance(archive_data, list) else 0,
            "emails": [],
            "ips": dns_records.get("A", []),
        }

        logger.info(
            "domain_intel_completed",
            domain=domain,
            subdomains=len(subdomains),
            technologies=len(technologies),
        )

        return IntelligenceResult(
            source="domain_intel",
            data_type="domain_intelligence",
            confidence=0.85,
            raw_data=processed,
            processed_data=processed,
            category="technical",
            severity="info" if len(subdomains) < 20 else "medium",
            metadata={"domain": domain},
        )

    async def _dns_lookup(self, domain: str) -> dict[str, list[str]]:
        """DNS record lookup using Cloudflare DoH."""
        records: dict[str, list[str]] = {}
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for rtype in record_types:
                try:
                    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
                    headers = {"accept": "application/dns-json"}
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            answers = [a["data"] for a in data.get("Answer", [])]
                            if answers:
                                records[rtype] = answers
                except Exception as e:
                    logger.debug("dns_lookup_error", domain=domain, type=rtype, error=str(e))

        return records

    async def _certificate_transparency(self, domain: str) -> list[str]:
        """Search crt.sh for subdomains via certificate transparency logs."""
        subdomains: set[str] = set()
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        certs = await resp.json()
                        for cert in certs[:500]:
                            for name in cert.get("name_value", "").split("\n"):
                                name = name.strip().lower()
                                if name.endswith(domain) and "*" not in name:
                                    subdomains.add(name)
        except Exception as e:
            logger.error("ct_lookup_error", domain=domain, error=str(e))

        return sorted(subdomains)

    async def _http_headers(self, domain: str) -> dict[str, str]:
        """Fetch HTTP headers for technology fingerprinting."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            headers = {"User-Agent": "Mozilla/5.0 (compatible; CerberusAI/1.0)"}
            async with aiohttp.ClientSession(
                timeout=timeout, headers=headers
            ) as session, session.get(
                f"https://{domain}", allow_redirects=True
            ) as resp:
                return dict(resp.headers)
        except Exception as e:
            logger.debug("http_headers_error", domain=domain, error=str(e))
            return {}

    async def _web_archive(self, domain: str) -> list[dict]:
        """Search Wayback Machine for archived snapshots."""
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = (
                    f"https://web.archive.org/cdx/search/cdx?url={domain}"
                    f"&output=json&limit=50&fl=timestamp,original,statuscode"
                )
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [
                            {"timestamp": r[0], "url": r[1], "status": r[2]}
                            for r in data[1:]
                        ]
        except Exception as e:
            logger.debug("archive_error", domain=domain, error=str(e))
        return []
