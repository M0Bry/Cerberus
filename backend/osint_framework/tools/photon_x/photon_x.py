"""
Photon X — Advanced Web Intelligence Crawler.

Version: 3.0.0
Features:
- Intelligent crawling with depth control
- Asset discovery and fingerprinting
- Sensitive data detection
- Technology stack identification
- Endpoint enumeration
- Email extraction
- Social link discovery
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


@dataclass
class WebAsset:
    """Discovered web asset."""
    url: str
    asset_type: str
    content_hash: str
    size: int
    source_page: str
    discovery_time: str
    metadata: dict | None = None


class PhotonX:
    """
    Advanced Web Intelligence Crawler.

    Usage:
        crawler = PhotonX()
        results = await crawler.crawl("https://example.com")
        crawler.save_results("results.json")
    """

    def __init__(self, config: dict | None = None):
        self.config = config or self._default_config()
        self.session: aiohttp.ClientSession | None = None
        self.visited_urls: set[str] = set()
        self.discovered_assets: list[WebAsset] = []
        self.endpoints: set[str] = set()
        self.emails: set[str] = set()
        self.social_links: set[str] = set()
        self.api_endpoints: set[str] = set()
        self.secrets: list[dict] = []
        self.js_files: set[str] = set()
        self.subdomains: set[str] = set()
        self.technologies: set[str] = set()
        self.base_domain: str = ""

    @staticmethod
    def _default_config() -> dict:
        return {
            "max_depth": 3,
            "timeout": 30,
            "max_concurrent": 10,
            "user_agent": "PhotonX/3.0",
            "respect_robots": True,
            "extract_js": True,
            "extract_css": True,
            "extract_images": True,
            "search_secrets": True,
            "search_endpoints": True,
            "search_emails": True,
            "search_social": True,
            "verify_ssl": False,
        }

    async def crawl(self, target_url: str) -> dict:
        """
        Start crawling a target URL.

        Args:
            target_url: URL to crawl.

        Returns:
            Dictionary with all discovered intelligence.
        """
        logger.info(f"Starting Photon X crawl: {target_url}")

        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc.split(":")[0]

        timeout = aiohttp.ClientTimeout(total=self.config["timeout"])
        connector = aiohttp.TCPConnector(ssl=self.config["verify_ssl"])
        headers = {"User-Agent": self.config["user_agent"]}

        async with aiohttp.ClientSession(
            timeout=timeout,
            headers=headers,
            connector=connector,
        ) as session:
            self.session = session
            await self._crawl_url(target_url, depth=0)

        return self._compile_results()

    async def _crawl_url(self, url: str, depth: int) -> None:
        """Recursively crawl URLs up to max_depth."""
        if depth > self.config["max_depth"] or url in self.visited_urls:
            return
        if not self._in_scope(url):
            return

        self.visited_urls.add(url)

        # Session must exist at this point because it is created in `crawl()`
        assert self.session is not None, "Session not initialised"

        try:
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status != 200:
                    return

                content_type = response.headers.get("content-type", "")
                content = await response.text()

                if "text/html" in content_type:
                    await self._parse_html(content, url, depth)
                elif "javascript" in content_type or url.endswith(".js"):
                    self._parse_javascript(content, url)
        except Exception as e:
            logger.debug(f"Crawl error {url}: {e}")

    def _in_scope(self, url: str) -> bool:
        """Check if URL is within scope."""
        domain = urlparse(url).netloc.split(":")[0]
        return domain == self.base_domain or domain.endswith(f".{self.base_domain}")

    async def _parse_html(self, html: str, url: str, depth: int) -> None:
        """Parse HTML content for links and assets."""
        soup = BeautifulSoup(html, "lxml")

        # Extract links
        for link in soup.find_all("a", href=True):
            href = urljoin(url, link["href"])
            if href not in self.visited_urls:
                asyncio.create_task(self._crawl_url(href, depth + 1))

        # Extract scripts
        if self.config["extract_js"]:
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                self.js_files.add(src)

        # Extract emails
        if self.config["search_emails"]:
            text = soup.get_text()
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            self.emails.update(emails)

        # Extract social links
        if self.config["search_social"]:
            self._find_social_links(html)

        # Find secrets
        if self.config["search_secrets"]:
            self._find_secrets(html, url)

        # Find endpoints
        if self.config["search_endpoints"]:
            self._find_endpoints(html)

        # Detect technologies (without response headers here)
        self._detect_technologies(html, {})

    def _parse_javascript(self, content: str, url: str) -> None:
        """Parse JavaScript for endpoints and secrets."""
        api_patterns = [
            r'["\'](/api/[^"\x27\s]+)["\x27]',
            r'["\'](/v[0-9]+/[^"\x27\s]+)["\x27]',
            r'fetch\(["\x27]([^"\x27\s]+)["\x27]',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            self.api_endpoints.update(matches)

        if self.config["search_secrets"]:
            self._find_secrets(content, url)

    def _find_secrets(self, content: str, source_url: str) -> None:
        """Find secrets and sensitive information."""
        patterns = {
            "API Key": r'(?i)(?:api[_-]?key|apikey)["\s:=]+["\x27]([a-zA-Z0-9_-]{20,})["\x27]',
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36}",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "Google API": r"AIza[0-9A-Za-z\-_]{35}",
            "Database URL": r"(?:mongodb|postgresql|mysql|redis)://[^/\s]+",
            "Password": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\x27]([^"\x27]+)["\x27]',
        }

        for secret_type, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)
                redacted = value[:10] + "..." if len(value) > 10 else value
                self.secrets.append({
                    "type": secret_type,
                    "value_redacted": redacted,
                    "source_url": source_url,
                    "confidence": "high" if len(value) > 20 else "medium",
                })

    def _find_social_links(self, content: str) -> None:
        """Find social media links."""
        patterns = [
            r"https?://(?:www\.)?twitter\.com/([^/\s\"'<>]+)",
            r"https?://(?:www\.)?github\.com/([^/\s\"'<>]+)",
            r"https?://(?:www\.)?linkedin\.com/(?:in|company)/([^/\s\"'<>]+)",
            r"https?://(?:www\.)?facebook\.com/([^/\s\"'<>]+)",
            r"https?://(?:www\.)?instagram\.com/([^/\s\"'<>]+)",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content)
            self.social_links.update(matches)

    def _find_endpoints(self, content: str) -> None:
        """Find API endpoints and paths."""
        patterns = [
            r'["\']/(?:api|v1|v2|graphql|auth|login|admin|dashboard|wp-admin|wp-json)/[^"\x27\s]*["\x27]',
            r'action=["\x27]([^"\x27]+)["\x27]',
        ]
        for pattern in patterns:
            endpoints = re.findall(pattern, content)
            self.endpoints.update(endpoints)

    def _detect_technologies(self, content: str, headers: dict) -> None:
        """Detect technologies from content and headers."""
        tech_indicators = {
            "WordPress": ["wp-content", "wp-includes"],
            "React": ["react", "react-dom"],
            "Angular": ["ng-", "angular"],
            "Vue.js": ["vue", "vuejs"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Django": ["django", "csrfmiddlewaretoken"],
            "Laravel": ["laravel", "csrf-token"],
            "Node.js": ["express", "npm"],
        }

        for tech, indicators in tech_indicators.items():
            if any(ind.lower() in content.lower() for ind in indicators):
                self.technologies.add(tech)

        server = headers.get("server") or headers.get("Server")
        if server:
            self.technologies.add(server)

    def _compile_results(self) -> dict:
        """Compile all discovered intelligence."""
        return {
            "crawl_summary": {
                "target_domain": self.base_domain,
                "pages_crawled": len(self.visited_urls),
                "crawl_time": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
                "max_depth": self.config["max_depth"],
            },
            "discovered_assets": {
                "javascript_files": len(self.js_files),
                "api_endpoints": len(self.api_endpoints),
                "other_endpoints": len(self.endpoints),
                "total_assets": len(self.discovered_assets),
            },
            "intelligence": {
                "emails": list(self.emails),
                "social_accounts": list(self.social_links),
                "subdomains": list(self.subdomains),
                "api_endpoints": list(self.api_endpoints | self.endpoints),
                "technologies": list(self.technologies),
            },
            "security_findings": {
                "secrets_found": len(self.secrets),
                "secrets": self.secrets,
            },
        }

    def save_results(self, filename: str) -> None:
        """Save crawl results to file."""
        results = self._compile_results()
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to: {filename}")
