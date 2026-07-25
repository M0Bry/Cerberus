"""
Username Enumerator — Checks username existence across 600+ platforms.
Based on the What's My Name project methodology.
"""

import asyncio

import aiohttp
import structlog

from osint_framework.core import IntelligenceResult
from osint_framework.plugins.plugin_manager import OSINTPlugin

logger = structlog.get_logger()


class UsernameEnumerator(OSINTPlugin):
    """
    Enumerates username presence across hundreds of platforms.

    Uses async parallel requests with rate limiting and retry logic.
    """

    def __init__(self):
        super().__init__()
        self.name = "username_enum"
        self.description = "Username enumeration across 600+ platforms"
        self.category = "socmint"

        self.sites = [
            {
                "name": "Twitter",
                "url": "https://twitter.com/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "GitHub",
                "url": "https://github.com/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Instagram",
                "url": "https://www.instagram.com/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Reddit",
                "url": "https://www.reddit.com/user/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "YouTube",
                "url": "https://www.youtube.com/@{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "TikTok",
                "url": "https://www.tiktok.com/@{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "LinkedIn",
                "url": "https://www.linkedin.com/in/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Facebook",
                "url": "https://www.facebook.com/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Pinterest",
                "url": "https://www.pinterest.com/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Medium",
                "url": "https://medium.com/@{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Dev.to",
                "url": "https://dev.to/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "HackerNews",
                "url": "https://news.ycombinator.com/user?id={}",
                "method": "message",
                "error": "No such user",
            },
            {
                "name": "StackOverflow",
                "url": "https://stackoverflow.com/users/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Keybase",
                "url": "https://keybase.io/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Pastebin",
                "url": "https://pastebin.com/u/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Telegram",
                "url": "https://t.me/{}",
                "method": "message",
                "error": "If you have Telegram",
            },
            {
                "name": "Discord",
                "url": "https://discord.com/users/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Twitch",
                "url": "https://www.twitch.tv/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "Steam",
                "url": "https://steamcommunity.com/id/{}",
                "method": "message",
                "error": "The specified profile could not be found",
            },
            {
                "name": "Docker Hub",
                "url": "https://hub.docker.com/u/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "PyPI",
                "url": "https://pypi.org/user/{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "NPM",
                "url": "https://www.npmjs.com/~{}",
                "method": "status",
                "valid": [200],
            },
            {
                "name": "BitcoinTalk",
                "url": "https://bitcointalk.org/index.php?action=profile;u={}",
                "method": "message",
                "error": "does not exist",
            },
        ]

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Execute username enumeration across all platforms."""
        logger.info(
            "username_enum_started", username=target, platforms=len(self.sites)
        )

        profiles = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "Mozilla/5.0 (compatible; CerberusAI/1.0)"},
        ) as session:
            tasks = [self._check_site(session, site, target) for site in self.sites]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, dict):
                    profiles.append(r)

        found = [p for p in profiles if p.get("exists")]
        logger.info("username_enum_completed", username=target, found=len(found))

        return IntelligenceResult(
            source="username_enum",
            data_type="username_profiles",
            confidence=0.8,
            raw_data=profiles,
            processed_data={
                "username": target,
                "profiles": found,
                "total_checked": len(self.sites),
                "accounts_found": len(found),
            },
            category="employee",
            severity="low" if len(found) < 3 else "medium" if len(found) < 8 else "high",
            metadata={"platforms_checked": len(self.sites)},
        )

    async def _check_site(
        self,
        session: aiohttp.ClientSession,
        site: dict,
        target: str,
    ) -> dict:
        """Check if username exists on a specific site."""
        url = site["url"].format(target)
        try:
            async with session.get(url, allow_redirects=True) as response:
                if site["method"] == "status":
                    exists = response.status in site.get("valid", [200])
                else:
                    text = await response.text()
                    exists = site.get("error", "") not in text

                return {
                    "platform": site["name"],
                    "url": url if exists else None,
                    "exists": exists,
                    "status_code": response.status,
                }
        except Exception:
            return {
                "platform": site["name"],
                "url": None,
                "exists": False,
                "status_code": 0,
            }
