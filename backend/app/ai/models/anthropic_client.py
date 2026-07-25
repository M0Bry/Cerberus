"""Anthropic Client — Claude 3 (Sonnet/Opus) integration."""

import httpx
import structlog

logger = structlog.get_logger()


class AnthropicClient:
    """Claude API client for alternative model routing."""

    def __init__(self, api_key: str = "", model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1/messages"

    async def chat(self, messages: list[dict], system: str = "", max_tokens: int = 4096) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            body["system"] = system

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.base_url, json=body, headers=headers, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]
