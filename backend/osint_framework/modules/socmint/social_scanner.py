"""
Social Scanner — Discovers social media profiles and analyzes digital footprint.
"""

import asyncio

import aiohttp
import structlog

from osint_framework.core import IntelligenceResult
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class SocialScanner(OSINTPlugin):
    """
    Scans social media platforms for organizational presence and employee exposure.

    Checks: Twitter, LinkedIn, Facebook, Instagram, YouTube, GitHub,
    Reddit, Medium, Dev.to, and more.
    """

    def __init__(self):
        super().__init__()
        self.name = "social_scanner"
        self.description = "Social media profile discovery and analysis"
        self.category = "socmint"

        self.platforms = [
            {"name": "Twitter", "url": "https://twitter.com/{}", "type": "social_media"},
            {
                "name": "LinkedIn",
                "url": "https://www.linkedin.com/company/{}",
                "type": "professional",
            },
            {"name": "Facebook", "url": "https://www.facebook.com/{}", "type": "social_media"},
            {"name": "Instagram", "url": "https://www.instagram.com/{}", "type": "social_media"},
            {"name": "YouTube", "url": "https://www.youtube.com/@{}", "type": "video"},
            {"name": "GitHub", "url": "https://github.com/{}", "type": "development"},
            {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "type": "social_media"},
            {"name": "Medium", "url": "https://medium.com/@{}", "type": "blogging"},
            {"name": "Dev.to", "url": "https://dev.to/{}", "type": "development"},
            {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "type": "social_media"},
            {"name": "Pinterest", "url": "https://www.pinterest.com/{}", "type": "social_media"},
            {"name": "Twitch", "url": "https://www.twitch.tv/{}", "type": "streaming"},
        ]

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Scan social media platforms for the target organization/username."""
        logger.info("social_scan_started", target=target)

        profiles = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0 (compatible; CerberusAI/1.0)"},
        ) as session:
            tasks = [
                self._check_platform(session, platform, target)
                for platform in self.platforms
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, dict) and r.get("exists"):
                    profiles.append(r)

        return IntelligenceResult(
            source="social_scanner",
            data_type="social_profiles",
            confidence=0.7,
            raw_data=profiles,
            processed_data={
                "profiles": profiles,
                "total_checked": len(self.platforms),
                "found": len(profiles),
            },
            category="employee",
            severity="low" if len(profiles) < 5 else "medium",
            metadata={"platforms_checked": len(self.platforms)},
        )

    async def _check_platform(
        self,
        session: aiohttp.ClientSession,
        platform: dict,
        target: str,
    ) -> dict:
        """Check if target exists on a specific platform."""
        url = platform["url"].format(target)
        try:
            async with session.get(url, allow_redirects=True) as response:
                exists = response.status == 200
                return {
                    "platform": platform["name"],
                    "url": url,
                    "exists": exists,
                    "status_code": response.status,
                    "category": platform["type"],
                }
        except Exception:
            return {
                "platform": platform["name"],
                "url": None,
                "exists": False,
                "status_code": 0,
            }
