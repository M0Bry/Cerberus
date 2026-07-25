"""Vulnerability Scan Tools — ZAP API, Nuclei, custom vulnerability checks."""

import httpx
import structlog

logger = structlog.get_logger()


class VulnScanTools:
    """Vulnerability scanning tool integrations."""

    async def check_headers(self, url: str) -> list[dict]:
        """Check for missing security headers."""
        findings = []
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(url, timeout=10)
                headers = resp.headers

                required = {
                    "strict-transport-security": "Missing HSTS header",
                    "x-content-type-options": "Missing X-Content-Type-Options",
                    "x-frame-options": "Missing X-Frame-Options (clickjacking risk)",
                    "content-security-policy": "Missing Content-Security-Policy",
                    "x-xss-protection": "Missing X-XSS-Protection",
                    "referrer-policy": "Missing Referrer-Policy",
                }

                for header, description in required.items():
                    if header not in headers:
                        findings.append({
                            "type": "misconfiguration",
                            "severity": "medium",
                            "title": f"Missing Security Header: {header}",
                            "description": description,
                            "url": url,
                        })
        except Exception as e:
            logger.error("header_check_error", url=url, error=str(e))
        return findings

    async def check_info_disclosure(self, url: str) -> list[dict]:
        """Check for information disclosure in headers and error pages."""
        findings = []
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(url, timeout=10)

                server = resp.headers.get("server")
                if server:
                    findings.append({
                        "type": "info_disclosure",
                        "severity": "low",
                        "title": f"Server Header Disclosed: {server}",
                        "description": "Server technology revealed in HTTP headers",
                    })

                powered = resp.headers.get("x-powered-by")
                if powered:
                    findings.append({
                        "type": "info_disclosure",
                        "severity": "low",
                        "title": f"Technology Disclosed: {powered}",
                        "description": "Backend technology revealed via X-Powered-By header",
                    })
        except Exception as e:
            logger.error("info_disclosure_error", error=str(e))
        return findings

    async def check_common_paths(self, base_url: str) -> list[dict]:
        """Check for common exposed paths."""
        paths = [
            "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
            "/admin", "/api/docs", "/swagger", "/.well-known/security.txt",
            "/backup", "/debug", "/trace", "/config",
        ]
        findings = []
        async with httpx.AsyncClient(follow_redirects=False) as client:
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}", timeout=5)
                    if resp.status_code == 200:
                        # Determine severity without a long inline expression
                        if path in ["/.env", "/.git/config", "/backup"]:
                            severity = "high"
                        else:
                            severity = "medium"
                        findings.append({
                            "type": "exposure",
                            "severity": severity,
                            "title": f"Exposed Path: {path}",
                            "description": f"HTTP 200 returned for {path}",
                            "url": f"{base_url}{path}",
                        })
                except Exception:
                    pass
        return findings
