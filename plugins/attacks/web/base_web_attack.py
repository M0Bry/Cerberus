"""
Base Web Attack — Base class for all web application attack plugins.
"""

from typing import Any

import aiohttp

from plugins.core.attack_context import AttackContext
from plugins.core.base_attack import BaseAttack


class BaseWebAttack(BaseAttack):
    """
    Base class for web application attacks.
    """

    def __init__(self) -> None:
        super().__init__()
        self.category = "web"
        self.detection_patterns: dict[str, list[str]] = {
            "success": [],
            "error": [],
            "false_positive": [],
        }

    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        context: AttackContext | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
    ) -> dict[str, Any] | None:
        """Send an HTTP request and return response data."""
        try:
            req_headers = {}
            if context:
                req_headers.update(context.headers)          # type: ignore[attr-defined]
                if context.auth_token:
                    req_headers["Authorization"] = f"Bearer {context.auth_token}"
            if headers:
                req_headers.update(headers)

            timeout = context.timeout if context else 30      # type: ignore[attr-defined]

            async with (
                aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    connector=aiohttp.TCPConnector(ssl=context.verify_ssl if context else True),  # type: ignore[attr-defined]
                ) as session,
                session.request(
                    method,
                    url,
                    headers=req_headers,
                    data=data,
                    cookies=cookies,
                    allow_redirects=True,
                ) as response,
            ):
                body = await response.text()
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body[:10000],
                    "url": str(response.url),
                }
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _check_patterns(self, body: str) -> str | None:
        """Check response body against detection patterns."""
        for pattern in self.detection_patterns.get("success", []):
            if pattern.lower() in body.lower():
                return pattern
        return None

    def _check_false_positive(self, body: str) -> bool:
        """Check if response matches known false positive patterns."""
        for pattern in self.detection_patterns.get("false_positive", []):
            if pattern.lower() in body.lower():
                return True
        return False
